package soc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (b *Backend) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", dashboardHandler())
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /api/dashboard", b.authenticate(http.HandlerFunc(b.dashboardHandler)))
	mux.Handle("GET /api/control/ai", b.authenticate(http.HandlerFunc(b.aiControlHandler)))
	mux.Handle("PATCH /api/control/ai", b.authenticate(http.HandlerFunc(b.setAIControlHandler)))
	mux.Handle("POST /api/incidents/{id}/queue", b.authenticate(http.HandlerFunc(b.queueIncidentHandler)))
	mux.Handle("DELETE /api/incidents/{id}/queue", b.authenticate(http.HandlerFunc(b.removeQueuedIncidentHandler)))
	mux.Handle("GET /api/clients", b.authenticate(http.HandlerFunc(b.listClientsHandler)))
	mux.Handle("GET /api/alerts", b.authenticate(http.HandlerFunc(b.listAlertsHandler)))
	mux.Handle("POST /api/alerts", b.authenticate(http.HandlerFunc(b.ingestAlertHandler)))
	mux.Handle("GET /api/incidents", b.authenticate(http.HandlerFunc(b.listIncidentsHandler)))
	mux.Handle("GET /api/incidents/{id}", b.authenticate(http.HandlerFunc(b.getIncidentHandler)))
	mux.Handle("PATCH /api/incidents/{id}", b.authenticate(http.HandlerFunc(b.updateIncidentHandler)))
	mux.Handle("POST /api/incidents/{id}/analyze", b.authenticate(http.HandlerFunc(b.analyzeIncidentHandler)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("requête HTTP interrompue: %v", recovered)
				writeError(w, http.StatusInternalServerError, "erreur interne")
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

func (b *Backend) aiControlHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := requestedTenant(r)
	if !ok {
		writeError(w, http.StatusForbidden, "client non autorisé")
		return
	}
	control, err := b.AIControl(r.Context(), tenantID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control)
}

func (b *Backend) setAIControlHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if payload.Enabled == nil {
		writeError(w, http.StatusBadRequest, "le champ enabled est obligatoire")
		return
	}
	if err := b.SetAIEnabled(r.Context(), *payload.Enabled); err != nil {
		writeInternalError(w, err)
		return
	}
	control, err := b.AIControl(r.Context(), tenantFromContext(r.Context()))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, control)
}

func (b *Backend) queueIncidentHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := requestedTenant(r)
	if !ok {
		writeError(w, http.StatusForbidden, "client non autorisé")
		return
	}
	err := b.QueueIncidentAnalysis(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident introuvable")
		return
	}
	if errors.Is(err, errAIJobInProgress) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	control, err := b.AIControl(r.Context(), tenantID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, control)
}

func (b *Backend) removeQueuedIncidentHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := requestedTenant(r)
	if !ok {
		writeError(w, http.StatusForbidden, "client non autorisé")
		return
	}
	err := b.RemoveQueuedIncidentAnalysis(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "traitement introuvable")
		return
	}
	if errors.Is(err, errAIJobInProgress) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, errAIJobNotRemovable) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) listClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients, _ := r.Context().Value(authorizedClientsContextKey{}).([]string)
	writeJSON(w, http.StatusOK, clients)
}

func (b *Backend) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.Header.Get("Authorization"))
		token = strings.TrimPrefix(token, "Bearer ")
		tenantID, ok := b.TenantForToken(token)
		if !ok {
			writeError(w, http.StatusUnauthorized, "jeton API invalide")
			return
		}
		clients, _ := b.ClientsForToken(token)
		ctx := context.WithValue(r.Context(), tenantContextKey{}, tenantID)
		ctx = context.WithValue(ctx, authorizedClientsContextKey{}, clients)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type tenantContextKey struct{}
type authorizedClientsContextKey struct{}

func tenantFromContext(ctx context.Context) string {
	tenantID, _ := ctx.Value(tenantContextKey{}).(string)
	return tenantID
}

func requestedTenant(r *http.Request) (string, bool) {
	selected := r.URL.Query().Get("client")
	if selected == "" {
		return tenantFromContext(r.Context()), true
	}
	clients, _ := r.Context().Value(authorizedClientsContextKey{}).([]string)
	for _, client := range clients {
		if client == selected {
			return selected, true
		}
	}
	return "", false
}

func (b *Backend) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	result, err := b.Dashboard(r.Context(), tenantFromContext(r.Context()))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (b *Backend) listAlertsHandler(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 100, 500)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var since time.Time
	if value := r.URL.Query().Get("since"); value != "" {
		since, err = time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since doit être une date RFC3339")
			return
		}
	}
	alerts, err := b.ListAlerts(r.Context(), tenantFromContext(r.Context()), limit, since)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (b *Backend) ingestAlertHandler(w http.ResponseWriter, r *http.Request) {
	var raw map[string]any
	if err := decodeBody(w, r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	alert, inserted, err := b.IngestAlert(r.Context(), tenantFromContext(r.Context()), raw)
	if err != nil {
		var validationErr *invalidAlertError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
		} else {
			writeInternalError(w, err)
		}
		return
	}
	status := http.StatusCreated
	if !inserted {
		status = http.StatusOK
	}
	writeJSON(w, status, alert)
}

func (b *Backend) listIncidentsHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := requestedTenant(r)
	if !ok {
		writeError(w, http.StatusForbidden, "client non autorisé")
		return
	}
	limit, err := queryLimit(r, 100, 500)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && !isIncidentStatus(status) {
		writeError(w, http.StatusBadRequest, "status invalide")
		return
	}
	incidents, err := b.ListIncidents(r.Context(), tenantID, status, limit)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, incidents)
}

func (b *Backend) getIncidentHandler(w http.ResponseWriter, r *http.Request) {
	incident, err := b.GetIncident(r.Context(), tenantFromContext(r.Context()), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident introuvable")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func (b *Backend) updateIncidentHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Status   string `json:"status"`
		Feedback string `json:"feedback"`
	}
	if err := decodeBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if payload.Status == "" && payload.Feedback == "" {
		writeError(w, http.StatusBadRequest, "fournissez status et/ou feedback")
		return
	}
	incident, err := b.UpdateIncident(r.Context(), tenantFromContext(r.Context()),
		r.PathValue("id"), payload.Status, payload.Feedback)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident introuvable")
		return
	}
	if errors.Is(err, errInvalidIncidentStatus) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func (b *Backend) analyzeIncidentHandler(w http.ResponseWriter, r *http.Request) {
	enabled, err := b.AIEnabled(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !enabled {
		writeError(w, http.StatusConflict, "l'analyse IA est en pause")
		return
	}
	incident, err := b.GetIncident(r.Context(), tenantFromContext(r.Context()), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident introuvable")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	analysis, err := b.analyzeIncident(r.Context(), incident)
	if err != nil {
		log.Printf("analyse Ollama échouée pour l'incident %s: %v", incident.ID, err)
		writeError(w, http.StatusBadGateway, "service d'analyse indisponible")
		return
	}
	if err := b.saveAnalysis(r.Context(), incident.TenantID, incident.ID, analysis); err != nil {
		writeInternalError(w, err)
		return
	}
	incident.Analysis = analysis
	writeJSON(w, http.StatusOK, map[string]any{"incident": incident, "analysis": analysis})
}

func (b *Backend) saveAnalysis(ctx context.Context, tenantID, incidentID, analysis string) error {
	result, err := b.db.ExecContext(ctx,
		`UPDATE incidents SET analysis = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`,
		analysis, formatDatabaseTime(time.Now()), tenantID, incidentID)
	if err != nil {
		return fmt.Errorf("enregistrer l'analyse de l'incident: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("vérifier l'enregistrement de l'analyse: %w", err)
	}
	if changed == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (b *Backend) analyzeIncident(ctx context.Context, incident Incident) (string, error) {
	return b.callOllama(ctx, incident)
}

func queryLimit(r *http.Request, fallback, maximum int) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > maximum {
		return 0, fmt.Errorf("limit doit être compris entre 1 et %d", maximum)
	}
	return limit, nil
}

func decodeBody(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("le corps JSON est obligatoire")
		}
		return fmt.Errorf("corps JSON invalide: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("le corps doit contenir un seul document JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encoder la réponse HTTP: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func isIncidentStatus(status string) bool {
	return status == "open" || status == "investigating" ||
		status == "resolved" || status == "false_positive"
}

func writeInternalError(w http.ResponseWriter, err error) {
	log.Printf("erreur API SOC: %v", err)
	writeError(w, http.StatusInternalServerError, "erreur interne")
}
