package soc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

func TestParseAlertTimestampAcceptsRFC3339AndCompactOffset(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		want      time.Time
	}{
		{
			name:      "RFC3339",
			timestamp: "2026-10-27T15:14:03.248+01:00",
			want:      time.Date(2026, 10, 27, 14, 14, 3, 248_000_000, time.UTC),
		},
		{
			name:      "Wazuh compact offset",
			timestamp: "2026-10-27T15:14:03.248+0100",
			want:      time.Date(2026, 10, 27, 14, 14, 3, 248_000_000, time.UTC),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAlertTimestamp(test.timestamp)
			if err != nil {
				t.Fatal(err)
			}
			if !got.UTC().Equal(test.want) {
				t.Fatalf("parsed timestamp = %s, want %s", got.UTC(), test.want)
			}
		})
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

func TestIncidentsExposeWazuhAgentMetadata(t *testing.T) {
	backend := testBackend(t, "")
	ctx := context.Background()
	payload := alertPayload("agent-details-event", highAlertLevel, "agent-42", "203.0.113.42")
	agent := payload["agent"].(map[string]any)
	agent["ip"] = "192.0.2.42"
	agent["labels"] = map[string]any{"group": "ClientB"}
	delete(payload["data"].(map[string]any), "srcip")
	wrappedPayload := map[string]any{"_id": "agent-details-event", "_source": payload}
	if _, _, err := backend.IngestAlert(ctx, "tenant-a", wrappedPayload); err != nil {
		t.Fatal(err)
	}

	incidents, err := backend.ListIncidents(ctx, "tenant-a", "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents = %#v, error = %v", incidents, err)
	}
	assertAgentMetadata := func(t *testing.T, incident Incident) {
		t.Helper()
		if incident.AgentLabel != "serveur-test" || incident.AgentIP != "192.0.2.42" ||
			incident.AgentID != "agent-42" || incident.SourceIP != "" ||
			len(incident.AgentGroups) != 1 || incident.AgentGroups[0] != "ClientB" {
			t.Fatalf("agent metadata = %#v", incident)
		}
	}
	assertAgentMetadata(t, incidents[0])

	incident, err := backend.GetIncident(ctx, "tenant-a", incidents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	assertAgentMetadata(t, incident)
	if len(incident.Alerts) != 1 || incident.Alerts[0].AgentIP != "192.0.2.42" ||
		len(incident.Alerts[0].AgentGroups) != 1 || incident.Alerts[0].AgentGroups[0] != "ClientB" {
		t.Fatalf("alert agent metadata = %#v", incident.Alerts)
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

func TestPausedAIWorkerKeepsForcedJobsQueued(t *testing.T) {
	var calls atomic.Int32
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"response": "Analyse"})
	}))
	defer ollama.Close()
	backend := testBackend(t, ollama.URL)
	ctx := context.Background()
	if _, _, err := backend.IngestAlert(ctx, "tenant-a",
		alertPayload("paused-event", highAlertLevel, "paused-agent", "203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	incidents, err := backend.ListIncidents(ctx, "tenant-a", "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents = %#v, error = %v", incidents, err)
	}
	if err := backend.SetAIEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := backend.QueueIncidentAnalysis(ctx, "tenant-a", incidents[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := backend.processNextAIJob(ctx); err != nil {
		t.Fatal(err)
	}
	control, err := backend.AIControl(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || control.Enabled || len(control.Queue) != 1 || control.Queue[0].Status != "pending" {
		t.Fatalf("paused AI unexpectedly processed its queue: calls=%d control=%#v", calls.Load(), control)
	}
	if err := backend.SetAIEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := backend.processNextAIJob(ctx); err != nil {
		t.Fatal(err)
	}
	control, err = backend.AIControl(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || len(control.Queue) != 1 || control.Queue[0].Status != "done" || !control.Queue[0].Forced {
		t.Fatalf("forced job did not run after resume: calls=%d control=%#v", calls.Load(), control)
	}
}

func TestAIPausePersistsAcrossBackendRestart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "soc.db")
	config := Config{
		DatabasePath: databasePath,
		Tenants:      map[string]string{"token-a": "tenant-a"},
	}
	first, err := NewBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.SetAIEnabled(context.Background(), false); err != nil {
		first.Close()
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := NewBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	enabled, err := second.AIEnabled(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("AI pause was lost after restarting the backend")
	}
}

func TestForceQueueReanalyzesCompletedIncidentAndChecksTenant(t *testing.T) {
	backend := testBackend(t, "")
	ctx := context.Background()
	if _, _, err := backend.IngestAlert(ctx, "tenant-a",
		alertPayload("finished-event", highAlertLevel, "finished-agent", "203.0.113.11")); err != nil {
		t.Fatal(err)
	}
	incidents, err := backend.ListIncidents(ctx, "tenant-a", "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents = %#v, error = %v", incidents, err)
	}
	incidentID := incidents[0].ID
	if _, err := backend.db.Exec(`UPDATE incident_ai_jobs SET status = 'done' WHERE incident_id = ?`, incidentID); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.db.Exec(`UPDATE incidents SET analysis = 'ancienne analyse' WHERE id = ?`, incidentID); err != nil {
		t.Fatal(err)
	}
	if err := backend.QueueIncidentAnalysis(ctx, "tenant-b", incidentID); err == nil {
		t.Fatal("tenant-b must not be able to queue tenant-a's incident")
	}
	if err := backend.QueueIncidentAnalysis(ctx, "tenant-a", incidentID); err != nil {
		t.Fatal(err)
	}
	var status string
	var forced, attempts int
	if err := backend.db.QueryRow(`SELECT status, forced, attempts FROM incident_ai_jobs WHERE incident_id = ?`,
		incidentID).Scan(&status, &forced, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || forced != 1 || attempts != 0 {
		t.Fatalf("requeued job has state %q, forced=%d, attempts=%d", status, forced, attempts)
	}
	refreshed, err := backend.GetIncident(ctx, "tenant-a", incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Analysis != "" {
		t.Fatalf("old analysis was not cleared before force reanalysis: %q", refreshed.Analysis)
	}
}

func TestRemoveQueuedIncidentAnalysis(t *testing.T) {
	backend := testBackend(t, "")
	ctx := context.Background()
	if _, _, err := backend.IngestAlert(ctx, "tenant-a",
		alertPayload("remove-event", highAlertLevel, "remove-agent", "203.0.113.12")); err != nil {
		t.Fatal(err)
	}
	incidents, err := backend.ListIncidents(ctx, "tenant-a", "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents = %#v, error = %v", incidents, err)
	}
	incidentID := incidents[0].ID
	if err := backend.QueueIncidentAnalysis(ctx, "tenant-a", incidentID); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveQueuedIncidentAnalysis(ctx, "tenant-b", incidentID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("remove with another tenant error = %v, want sql.ErrNoRows", err)
	}
	if err := backend.RemoveQueuedIncidentAnalysis(ctx, "tenant-a", incidentID); err != nil {
		t.Fatalf("remove pending job: %v", err)
	}
	if err := backend.QueueIncidentAnalysis(ctx, "tenant-a", incidentID); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.db.Exec(`UPDATE incident_ai_jobs SET status = 'processing' WHERE incident_id = ?`, incidentID); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveQueuedIncidentAnalysis(ctx, "tenant-a", incidentID); !errors.Is(err, errAIJobInProgress) {
		t.Fatalf("remove processing job error = %v, want errAIJobInProgress", err)
	}
}

func TestAPIListsAgentGroupsForExistingToken(t *testing.T) {
	backend, err := NewBackend(Config{
		DatabasePath: filepath.Join(t.TempDir(), "soc.db"),
		Tenants:      map[string]string{"token-a": "tenant-a", "token-b": "tenant-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close backend: %v", err)
		}
	})
	for _, group := range []string{"ClientA", "ClientB"} {
		payload := alertPayload("client-filter-"+group, highAlertLevel, "agent-"+group, "")
		payload["agent"].(map[string]any)["labels"] = map[string]any{"group": group}
		if _, _, err := backend.IngestAlert(context.Background(), "tenant-a", payload); err != nil {
			t.Fatal(err)
		}
	}

	server := httptest.NewServer(backend.Handler())
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/clients", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token-a")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var clients []string
	if err := json.NewDecoder(response.Body).Decode(&clients); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || len(clients) != 2 ||
		clients[0] != "ClientA" || clients[1] != "ClientB" {
		t.Fatalf("group response = (%d, %#v), want ClientA and ClientB", response.StatusCode, clients)
	}

	request, err = http.NewRequest(http.MethodGet, server.URL+"/api/incidents?limit=500", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token-a")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("incidents response status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var incidents []Incident
	if err := json.NewDecoder(response.Body).Decode(&incidents); err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 2 {
		t.Fatalf("incident count = %d, want 2", len(incidents))
	}
	for _, incident := range incidents {
		if incident.TenantID != "tenant-a" || len(incident.AgentGroups) != 1 ||
			(incident.AgentGroups[0] != "ClientA" && incident.AgentGroups[0] != "ClientB") {
			t.Fatalf("incident group/tenant = %#v", incident)
		}
	}

	request, err = http.NewRequest(http.MethodGet, server.URL+"/api/incidents?client=tenant-c", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token-a")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var unfilteredIncidents []Incident
	if err := json.NewDecoder(response.Body).Decode(&unfilteredIncidents); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unfiltered incidents status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	for _, incident := range unfilteredIncidents {
		if incident.TenantID != "tenant-a" {
			t.Fatalf("client query escaped token tenant: %#v", incident)
		}
	}
}

func TestIncidentDetailAndStatusUpdateAPI(t *testing.T) {
	backend := testBackend(t, "")
	_, _, err := backend.IngestAlert(context.Background(), "tenant-a",
		alertPayload("incident-detail-event", highAlertLevel, "incident-detail-agent", "203.0.113.42"))
	if err != nil {
		t.Fatal(err)
	}
	incidents, err := backend.ListIncidents(context.Background(), "tenant-a", "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents = %#v, error = %v", incidents, err)
	}
	incidentID := incidents[0].ID
	server := httptest.NewServer(backend.Handler())
	defer server.Close()
	token := ""
	for configuredToken, tenant := range backend.config.Tenants {
		if tenant == "tenant-a" {
			token = configuredToken
			break
		}
	}

	request, err := http.NewRequest(http.MethodGet,
		server.URL+"/api/incidents/"+incidentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var incident Incident
	if err := json.NewDecoder(response.Body).Decode(&incident); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || len(incident.Alerts) != 1 {
		t.Fatalf("incident detail response = (%d, alerts=%d)", response.StatusCode, len(incident.Alerts))
	}

	request, err = http.NewRequest(http.MethodPatch,
		server.URL+"/api/incidents/"+incidentID,
		jsonBody(map[string]string{"status": "investigating", "feedback": "Pris en charge"}))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(&incident); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || incident.Status != "investigating" ||
		len(incident.Feedback) != 1 || incident.Feedback[0] != "Pris en charge" {
		t.Fatalf("incident update response = (%d, %#v)", response.StatusCode, incident)
	}
}

func TestAPIRequiresTenantTokenAndReturnsTenantData(t *testing.T) {
	backend := testBackend(t, "")
	server := httptest.NewServer(backend.Handler())
	defer server.Close()

	pageRequest, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	pageResponse, err := client.Do(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	if pageResponse.StatusCode != http.StatusOK ||
		!strings.Contains(pageResponse.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		pageResponse.Body.Close()
		t.Fatalf("dashboard response status/security/location = %d / %q / %q",
			pageResponse.StatusCode, pageResponse.Header.Get("Content-Security-Policy"), pageResponse.Header.Get("Location"))
	}
	pageResponse.Body.Close()
	maintenanceResponse, err := client.Get(server.URL + "/maintenance")
	if err != nil {
		t.Fatal(err)
	}
	if maintenanceResponse.StatusCode != http.StatusOK {
		maintenanceResponse.Body.Close()
		t.Fatalf("maintenance page status = %d, want %d", maintenanceResponse.StatusCode, http.StatusOK)
	}
	maintenanceResponse.Body.Close()
	assetResponse, err := client.Get(server.URL + "/assets/dashboard.js")
	if err != nil {
		t.Fatal(err)
	}
	if assetResponse.StatusCode != http.StatusOK {
		assetResponse.Body.Close()
		t.Fatalf("dashboard JavaScript status = %d, want %d", assetResponse.StatusCode, http.StatusOK)
	}
	assetResponse.Body.Close()
	maintenanceAssetResponse, err := client.Get(server.URL + "/assets/maintenance.js")
	if err != nil {
		t.Fatal(err)
	}
	if maintenanceAssetResponse.StatusCode != http.StatusOK {
		maintenanceAssetResponse.Body.Close()
		t.Fatalf("maintenance JavaScript status = %d, want %d", maintenanceAssetResponse.StatusCode, http.StatusOK)
	}
	maintenanceAssetResponse.Body.Close()

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
	request, err = http.NewRequest(http.MethodPatch, server.URL+"/api/control/ai",
		jsonBody(map[string]bool{"enabled": false}))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token-a")
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("AI control status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	response.Body.Close()
	incidents, err := backend.ListIncidents(context.Background(), "tenant-a", "", 10)
	if err != nil || len(incidents) != 1 {
		t.Fatalf("incidents = %#v, error = %v", incidents, err)
	}
	request, err = http.NewRequest(http.MethodPost,
		server.URL+"/api/incidents/"+incidents[0].ID+"/analyze", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token-a")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("manual analysis while paused status = %d, want %d", response.StatusCode, http.StatusConflict)
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
	backend.config.WazuhSources = []WazuhSource{source}
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
	statuses := backend.WazuhStatus("tenant-a")
	if len(statuses) != 1 || statuses[0].State != "receiving" ||
		statuses[0].AlertsReceived != 1 || statuses[0].LastCheck == nil ||
		statuses[0].LastSuccess == nil || statuses[0].LastAlert == nil {
		t.Fatalf("Wazuh status after successful polls = %#v", statuses)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/wazuh/status", nil)
	request = request.WithContext(context.WithValue(request.Context(), tenantContextKey{}, "tenant-a"))
	backend.wazuhStatusHandler(response, request)
	var statusResponse struct {
		Configured bool                `json:"configured"`
		Sources    []WazuhSourceStatus `json:"sources"`
	}
	if err := json.NewDecoder(response.Body).Decode(&statusResponse); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !statusResponse.Configured ||
		len(statusResponse.Sources) != 1 || statusResponse.Sources[0].State != "receiving" {
		t.Fatalf("Wazuh status API response = (%d, %#v)", response.Code, statusResponse)
	}
}

func TestWazuhPollStatusReportsConnectionFailure(t *testing.T) {
	backend := testBackend(t, "")
	source := WazuhSource{
		TenantID:    "tenant-a",
		URL:         "://invalid-url",
		AlertsIndex: "wazuh-alerts-*",
		BatchSize:   10,
	}
	backend.config.WazuhSources = []WazuhSource{source}
	if err := backend.pollWazuh(context.Background(), source); err == nil {
		t.Fatal("expected invalid Wazuh URL to fail")
	}
	statuses := backend.WazuhStatus("tenant-a")
	if len(statuses) != 1 || statuses[0].State != "error" || statuses[0].Error == "" ||
		statuses[0].LastCheck == nil || statuses[0].LastSuccess != nil {
		t.Fatalf("Wazuh status after connection failure = %#v", statuses)
	}
}

func jsonBody(value any) *strings.Reader {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return strings.NewReader(string(encoded))
}
