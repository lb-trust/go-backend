package soc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxAIJobAttempts = 3

type WazuhSourceStatus struct {
	TenantID       string     `json:"tenant_id"`
	AlertsIndex    string     `json:"alerts_index"`
	State          string     `json:"state"`
	LastCheck      *time.Time `json:"last_check,omitempty"`
	LastSuccess    *time.Time `json:"last_success,omitempty"`
	LastAlert      *time.Time `json:"last_alert,omitempty"`
	AlertsReceived int        `json:"alerts_received"`
	Error          string     `json:"error,omitempty"`
}

func wazuhSourceStatusKey(source WazuhSource) string {
	return source.TenantID + "\x00" + source.URL + "\x00" + source.AlertsIndex
}

func (b *Backend) WazuhStatus(tenantID string) []WazuhSourceStatus {
	now := time.Now().UTC()
	b.wazuhStatusMu.RLock()
	defer b.wazuhStatusMu.RUnlock()
	statuses := make([]WazuhSourceStatus, 0, len(b.config.WazuhSources))
	for _, source := range b.config.WazuhSources {
		if source.TenantID != tenantID {
			continue
		}
		status, exists := b.wazuhStatuses[wazuhSourceStatusKey(source)]
		if !exists {
			status = WazuhSourceStatus{
				TenantID:    source.TenantID,
				AlertsIndex: source.AlertsIndex,
				State:       "unknown",
			}
		} else if status.Error == "" {
			state := "idle"
			freshness := 2 * b.config.WazuhPollInterval
			if freshness <= 0 {
				freshness = 2 * time.Minute
			}
			if status.LastAlert != nil && now.Sub(*status.LastAlert) <= freshness {
				state = "receiving"
			}
			status.State = state
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("générer un identifiant: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func (b *Backend) callOllama(ctx context.Context, incident Incident) (string, error) {
	payload := map[string]any{
		"model":  b.config.OllamaModel,
		"stream": false,
		"prompt": fmt.Sprintf(
			"Tu es un analyste SOC. Analyse cet incident de sécurité. Sépare les faits, le risque, les hypothèses et les actions recommandées. N'invente pas de faits.\n\nIncident: %s\nSévérité: %s (score %d/100)\nStatut: %s\nAgent: %s (%s)\nIP source: %s\nOccurrences: %d\n",
			incident.Title, incident.Severity, incident.Score, incident.Status,
			incident.AgentName(), incident.AgentID, incident.SourceIP, incident.Occurrences),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encoder la demande Ollama: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.config.OllamaURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("créer la requête Ollama: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := *b.httpClient
	client.Timeout = 2 * time.Minute
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("contacter Ollama: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Ollama a répondu avec le statut HTTP %d", response.StatusCode)
	}
	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes)).Decode(&result); err != nil {
		return "", fmt.Errorf("décoder la réponse Ollama: %w", err)
	}
	if strings.TrimSpace(result.Response) == "" {
		return "", fmt.Errorf("Ollama a renvoyé une analyse vide")
	}
	return strings.TrimSpace(result.Response), nil
}

func (incident Incident) AgentName() string {
	if len(incident.Alerts) > 0 {
		return incident.Alerts[0].AgentName
	}
	return "inconnu"
}

func (b *Backend) StartCollectors(ctx context.Context) {
	for _, source := range b.config.WazuhSources {
		source := source
		b.workers.Add(1)
		go b.runCollector(ctx, source)
	}
}

func (b *Backend) StartAIWorker(ctx context.Context) {
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := b.processNextAIJob(ctx); err != nil && ctx.Err() == nil {
				log.Printf("traitement de la file d'analyse SOC: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (b *Backend) processNextAIJob(ctx context.Context) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("démarrer la réservation d'une analyse: %w", err)
	}
	defer tx.Rollback()
	var enabledValue string
	if err := tx.QueryRowContext(ctx,
		`SELECT value FROM soc_settings WHERE key = 'ai_enabled'`).Scan(&enabledValue); err != nil {
		return fmt.Errorf("lire le réglage de la file IA: %w", err)
	}
	if enabledValue != "true" {
		return nil
	}
	var jobID int64
	var incidentID, tenantID string
	err = tx.QueryRowContext(ctx,
		`SELECT j.id, j.incident_id, i.tenant_id
		 FROM incident_ai_jobs j JOIN incidents i ON i.id = j.incident_id
		 WHERE j.status = 'pending' AND j.next_attempt <= ?
		 ORDER BY j.created_at LIMIT 1`,
		formatDatabaseTime(time.Now())).Scan(&jobID, &incidentID, &tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("rechercher une analyse à traiter: %w", err)
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE incident_ai_jobs SET status = 'processing' WHERE id = ? AND status = 'pending'`,
		jobID)
	if err != nil {
		return fmt.Errorf("réserver une analyse: %w", err)
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("vérifier la réservation de l'analyse: %w", err)
	}
	if claimed == 0 {
		return nil
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("valider la réservation d'une analyse: %w", err)
	}
	if err := b.executeAIJob(ctx, incidentID, tenantID); err != nil {
		var attempts int
		if queryErr := b.db.QueryRowContext(ctx,
			`SELECT attempts FROM incident_ai_jobs WHERE id = ?`, jobID).Scan(&attempts); queryErr != nil {
			return fmt.Errorf("lire les tentatives d'analyse après échec: %w", queryErr)
		}
		attempts++
		status := "pending"
		nextAttempt := time.Now().UTC().Add(time.Minute)
		if attempts >= maxAIJobAttempts {
			status = "failed"
		}
		if _, updateErr := b.db.ExecContext(ctx,
			`UPDATE incident_ai_jobs SET status = ?, attempts = ?, next_attempt = ? WHERE id = ?`,
			status, attempts, formatDatabaseTime(nextAttempt), jobID); updateErr != nil {
			return fmt.Errorf("programmer une nouvelle tentative d'analyse: %w", updateErr)
		}
		log.Printf("analyse automatique échouée pour l'incident %s (tentative %d/%d): %v",
			incidentID, attempts, maxAIJobAttempts, err)
		return nil
	}
	if _, err := b.db.ExecContext(ctx,
		`UPDATE incident_ai_jobs SET status = 'done' WHERE id = ?`, jobID); err != nil {
		return fmt.Errorf("terminer l'analyse automatique: %w", err)
	}
	return nil
}

func (b *Backend) executeAIJob(ctx context.Context, incidentID, tenantID string) error {
	incident, err := b.GetIncident(ctx, tenantID, incidentID)
	if err != nil {
		return fmt.Errorf("charger l'incident à analyser: %w", err)
	}
	analysis := incident.Analysis
	if analysis == "" {
		analysis, err = b.analyzeIncident(ctx, incident)
		if err != nil {
			return err
		}
		if err := b.saveAnalysis(ctx, tenantID, incidentID, analysis); err != nil {
			return err
		}
	}
	if b.config.IrisBaseURL != "" {
		if err := b.PublishIncidentToIRIS(ctx, incident, analysis); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) runCollector(ctx context.Context, source WazuhSource) {
	defer b.workers.Done()
	ticker := time.NewTicker(b.config.WazuhPollInterval)
	defer ticker.Stop()
	for {
		if err := b.pollWazuh(ctx, source); err != nil && ctx.Err() == nil {
			log.Printf("collecte Wazuh pour le tenant %q: %v", source.TenantID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (b *Backend) pollWazuh(ctx context.Context, source WazuhSource) (pollErr error) {
	status := WazuhSourceStatus{
		TenantID:    source.TenantID,
		AlertsIndex: source.AlertsIndex,
		State:       "idle",
	}
	checkedAt := time.Now().UTC()
	status.LastCheck = &checkedAt
	defer func() {
		if pollErr != nil {
			status.State = "error"
			status.Error = pollErr.Error()
		} else {
			succeededAt := time.Now().UTC()
			status.LastSuccess = &succeededAt
			status.Error = ""
		}
		b.wazuhStatusMu.Lock()
		previous := b.wazuhStatuses[wazuhSourceStatusKey(source)]
		if status.LastAlert == nil {
			status.LastAlert = previous.LastAlert
		}
		b.wazuhStatuses[wazuhSourceStatusKey(source)] = status
		b.wazuhStatusMu.Unlock()
	}()

	base, err := url.Parse(strings.TrimRight(source.URL, "/"))
	if err != nil {
		return fmt.Errorf("analyser l'URL de l'Indexer: %w", err)
	}
	indexPath := strings.ReplaceAll(url.PathEscape(source.AlertsIndex), "%2A", "*")
	base.Path = strings.TrimRight(base.Path, "/") + "/" + indexPath + "/_search"
	query := map[string]any{
		"size": source.BatchSize,
		"sort": []any{map[string]any{"timestamp": map[string]string{"order": "asc"}}},
		"query": map[string]any{"range": map[string]any{
			"timestamp": map[string]string{"gte": time.Now().UTC().Add(-b.config.WazuhPollInterval - time.Minute).Format(time.RFC3339)},
		}},
	}
	body, err := json.Marshal(query)
	if err != nil {
		return fmt.Errorf("encoder la requête Wazuh: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("créer la requête Wazuh: %w", err)
	}
	request.SetBasicAuth(source.Username, source.Password)
	request.Header.Set("Content-Type", "application/json")

	client := b.httpClient
	if source.VerifyTLS != nil && !*source.VerifyTLS {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client = &http.Client{Timeout: b.httpClient.Timeout, Transport: transport}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("contacter Wazuh Indexer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Wazuh Indexer a répondu avec le statut HTTP %d", response.StatusCode)
	}
	var result struct {
		Hits struct {
			Hits []struct {
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes*10)).Decode(&result); err != nil {
		return fmt.Errorf("décoder les alertes Wazuh: %w", err)
	}
	status.AlertsReceived = len(result.Hits.Hits)
	for _, hit := range result.Hits.Hits {
		if hit.Source == nil {
			return fmt.Errorf("Wazuh a renvoyé une alerte sans document source")
		}
		if rawTimestamp, ok := hit.Source["timestamp"].(string); ok {
			if timestamp, err := parseAlertTimestamp(rawTimestamp); err == nil &&
				(status.LastAlert == nil || timestamp.After(*status.LastAlert)) {
				status.LastAlert = &timestamp
			}
		}
		hit.Source["_id"] = hit.ID
		if _, _, err := b.IngestAlert(ctx, source.TenantID, hit.Source); err != nil {
			return fmt.Errorf("ingérer l'alerte Wazuh %q: %w", hit.ID, err)
		}
	}
	return nil
}

func (b *Backend) PublishIncidentToIRIS(ctx context.Context, incident Incident, analysis string) error {
	if b.config.IrisBaseURL == "" {
		return nil
	}
	details, err := json.Marshal(map[string]any{
		"incident": incident,
		"alerts":   incident.Alerts,
		"analysis": analysis,
	})
	if err != nil {
		return fmt.Errorf("encoder les détails de l'événement IRIS: %w", err)
	}
	payload := map[string]any{
		"event_title":            "Analyse SOC: " + truncate(incident.Title, 200),
		"event_in_graph":         true,
		"event_in_summary":       true,
		"event_content":          analysis,
		"event_raw":              string(details),
		"event_source":           "SOC Backend / Ollama",
		"event_assets":           []any{},
		"event_iocs":             []any{},
		"event_category_id":      "1",
		"event_color":            "",
		"event_date":             time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		"event_tags":             "SOC,Wazuh,Ollama",
		"event_tz":               "+00:00",
		"custom_attributes":      map[string]any{},
		"event_sync_iocs_assets": false,
		"cid":                    b.config.IrisCaseID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoder l'événement IRIS: %w", err)
	}
	endpoint := strings.TrimRight(b.config.IrisBaseURL, "/") + "/case/timeline/events/add"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("créer la requête IRIS: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+b.config.IrisAPIKey)
	response, err := b.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("contacter IRIS DFIR: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("IRIS DFIR a répondu avec le statut HTTP %d", response.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes)).Decode(&result); err != nil {
		return fmt.Errorf("décoder la réponse IRIS DFIR: %w", err)
	}
	if result["success"] == false {
		return fmt.Errorf("IRIS DFIR a refusé l'événement")
	}
	if status, ok := result["status"].(string); ok {
		switch strings.ToLower(status) {
		case "error", "failed", "failure":
			return fmt.Errorf("IRIS DFIR a refusé l'événement")
		}
	}
	return nil
}

func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
