package soc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testBackend(t *testing.T, ollamaURL string) *Backend {
	t.Helper()
	backend, err := NewBackend(Config{
		DatabasePath: filepath.Join(t.TempDir(), "soc.db"),
		Tenants:      map[string]string{"token-a": "tenant-a", "token-b": "tenant-b"},
		OllamaURL:    ollamaURL,
		OllamaModel:  "test-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close backend: %v", err)
		}
	})
	return backend
}

func alertPayload(id string, level int, agentID, sourceIP string) map[string]any {
	return map[string]any{
		"id":        id,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"rule": map[string]any{
			"id":          "5710",
			"level":       level,
			"description": "Tentative de connexion",
		},
		"agent": map[string]any{"id": agentID, "name": "serveur-test"},
		"data":  map[string]any{"srcip": sourceIP},
	}
}

func TestIngestGroupsAlertsAndDeduplicatesWazuhIDs(t *testing.T) {
	backend := testBackend(t, "")
	ctx := context.Background()

	first, inserted, err := backend.IngestAlert(ctx, "tenant-a", alertPayload("evt-1", 5, "agent-1", "192.0.2.1"))
	if err != nil || !inserted {
		t.Fatalf("first ingest = (%v, %v), want inserted: %v", first, inserted, err)
	}
	second, inserted, err := backend.IngestAlert(ctx, "tenant-a", alertPayload("evt-2", 5, "agent-1", "192.0.2.2"))
	if err != nil || !inserted {
		t.Fatalf("second ingest = (%v, %v), want inserted: %v", second, inserted, err)
	}
	if first.ID != second.ID {
		t.Fatalf("group IDs differ: %q and %q", first.ID, second.ID)
	}
	if second.Occurrences != 2 || second.Occurrences6h != 2 {
		t.Fatalf("occurrences = %d / %d, want 2 / 2", second.Occurrences, second.Occurrences6h)
	}
	if second.SourceIPCounts["192.0.2.1"] != 1 || second.SourceIPCounts["192.0.2.2"] != 1 {
		t.Fatalf("source IP counts = %#v", second.SourceIPCounts)
	}

	duplicate, inserted, err := backend.IngestAlert(ctx, "tenant-a", alertPayload("evt-2", 5, "agent-1", "192.0.2.2"))
	if err != nil || inserted {
		t.Fatalf("duplicate ingest inserted=%v, error=%v", inserted, err)
	}
	if duplicate.Occurrences != 2 {
		t.Fatalf("duplicate inflated occurrence count to %d", duplicate.Occurrences)
	}
}

func TestAlertsAreIsolatedByTenant(t *testing.T) {
	backend := testBackend(t, "")
	ctx := context.Background()
	payload := alertPayload("same-wazuh-id", 12, "agent-1", "198.51.100.4")
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if _, _, err := backend.IngestAlert(ctx, tenant, payload); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		alerts, err := backend.ListAlerts(ctx, tenant, 10, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if len(alerts) != 1 || alerts[0].TenantID != tenant {
			t.Fatalf("alerts for %q = %#v", tenant, alerts)
		}
	}
}

func TestLowSeverityThresholdQueuesAutomaticAnalysis(t *testing.T) {
	backend := testBackend(t, "")
	ctx := context.Background()
	for i := 1; i <= lowAlertAIThreshold; i++ {
		if _, _, err := backend.IngestAlert(ctx, "tenant-a",
			alertPayload(fmt.Sprintf("low-%d", i), 4, "agent-low", "203.0.113.8")); err != nil {
			t.Fatalf("ingest alert %d: %v", i, err)
		}
		var count int
		if err := backend.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM incident_ai_jobs`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		want := 0
		if i >= lowAlertAIThreshold {
			want = 1
		}
		if count != want {
			t.Fatalf("queued jobs after %d alerts = %d, want %d", i, count, want)
		}
	}
}

func TestAPIRequiresTenantTokenAndReturnsTenantData(t *testing.T) {
	backend := testBackend(t, "")
	server := httptest.NewServer(backend.Handler())
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/alerts", jsonBody(alertPayload("evt", 5, "agent", "")))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}

	request, err = http.NewRequest(http.MethodPost, server.URL+"/api/alerts", jsonBody(alertPayload("evt", 5, "agent", "")))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token-a")
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("authenticated status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
}

func TestAutomaticAnalysisPublishesOnlyAfterOllama(t *testing.T) {
	var ollamaCalls, irisCalls atomic.Int32
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ollamaCalls.Add(1)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]string{"response": "Analyse de test"})
	}))
	defer ollama.Close()
	iris := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		irisCalls.Add(1)
		if r.URL.Path != "/case/timeline/events/add" {
			t.Errorf("IRIS path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer iris-key" {
			t.Errorf("IRIS authorization header = %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer iris.Close()

	backend := testBackend(t, ollama.URL)
	backend.config.IrisBaseURL = iris.URL
	backend.config.IrisAPIKey = "iris-key"
	backend.config.IrisCaseID = 123
	if _, _, err := backend.IngestAlert(context.Background(), "tenant-a",
		alertPayload("critical-event", highAlertLevel, "agent-critical", "198.51.100.9")); err != nil {
		t.Fatal(err)
	}
	if err := backend.processNextAIJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ollamaCalls.Load() != 1 || irisCalls.Load() != 1 {
		t.Fatalf("Ollama calls = %d and IRIS calls = %d, want 1 each", ollamaCalls.Load(), irisCalls.Load())
	}
	var status string
	if err := backend.db.QueryRow(`SELECT status FROM incident_ai_jobs`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "done" {
		t.Fatalf("AI job status = %q, want done", status)
	}
}

func TestIRISRetryReusesSavedAnalysis(t *testing.T) {
	var ollamaCalls, irisCalls atomic.Int32
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ollamaCalls.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"response": "Analyse persistée"})
	}))
	defer ollama.Close()
	iris := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if irisCalls.Add(1) == 1 {
			http.Error(w, "indisponible", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer iris.Close()

	backend := testBackend(t, ollama.URL)
	backend.config.IrisBaseURL = iris.URL
	backend.config.IrisAPIKey = "iris-key"
	backend.config.IrisCaseID = 123
	if _, _, err := backend.IngestAlert(context.Background(), "tenant-a",
		alertPayload("retry-event", highAlertLevel, "agent-retry", "198.51.100.10")); err != nil {
		t.Fatal(err)
	}
	if err := backend.processNextAIJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.db.Exec(`UPDATE incident_ai_jobs SET next_attempt = ?`,
		formatDatabaseTime(time.Now().Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := backend.processNextAIJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ollamaCalls.Load() != 1 || irisCalls.Load() != 2 {
		t.Fatalf("Ollama calls = %d and IRIS calls = %d, want 1 and 2",
			ollamaCalls.Load(), irisCalls.Load())
	}
}

func TestWazuhPollerIngestsAndDeduplicatesIndexerResults(t *testing.T) {
	var calls atomic.Int32
	indexer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/wazuh-alerts-*/_search" {
			t.Errorf("Wazuh path = %q", r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "reader" || password != "test-password" {
			t.Errorf("unexpected Wazuh credentials")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"hits": []any{
				map[string]any{
					"_id":     "indexer-event",
					"_source": alertPayload("", 5, "indexer-agent", "203.0.113.12"),
				},
			}},
		})
	}))
	defer indexer.Close()
	backend := testBackend(t, "")
	verifyTLS := true
	source := WazuhSource{
		TenantID:    "tenant-a",
		URL:         indexer.URL,
		Username:    "reader",
		Password:    "test-password",
		VerifyTLS:   &verifyTLS,
		AlertsIndex: "wazuh-alerts-*",
		BatchSize:   10,
	}
	for range 2 {
		if err := backend.pollWazuh(context.Background(), source); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := backend.ListAlerts(context.Background(), "tenant-a", 10, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(alerts) != 1 || alerts[0].Occurrences != 1 {
		t.Fatalf("polls=%d, alerts=%#v; want two polls and one occurrence", calls.Load(), alerts)
	}
}

func jsonBody(value any) *strings.Reader {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return strings.NewReader(string(encoded))
}
