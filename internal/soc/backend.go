package soc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	lowAlertWindow      = 6 * time.Hour
	highAlertWindow     = 30 * time.Minute
	incidentWindow      = 30 * time.Minute
	lowAlertAIThreshold = 40
	highAlertLevel      = 10
	maxRequestBytes     = 1_000_000
	databaseTimeLayout  = "2006-01-02T15:04:05.000000000Z"
)

type invalidAlertError struct {
	err error
}

func (e *invalidAlertError) Error() string {
	return e.err.Error()
}

func (e *invalidAlertError) Unwrap() error {
	return e.err
}

var errInvalidIncidentStatus = errors.New("status doit être open, investigating, resolved ou false_positive")

type Backend struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	workers    sync.WaitGroup
}

type Alert struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	WazuhID        string          `json:"wazuh_id,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
	RuleID         string          `json:"rule_id"`
	RuleLevel      int             `json:"rule_level"`
	Description    string          `json:"description"`
	AgentID        string          `json:"agent_id,omitempty"`
	AgentName      string          `json:"agent_name"`
	AgentIP        string          `json:"agent_ip,omitempty"`
	AgentGroups    []string        `json:"agent_groups"`
	SourceIP       string          `json:"source_ip,omitempty"`
	DestIP         string          `json:"dest_ip,omitempty"`
	Location       string          `json:"location,omitempty"`
	FirstSeen      time.Time       `json:"first_seen"`
	LastSeen       time.Time       `json:"last_seen"`
	Occurrences    int             `json:"occurrences"`
	Occurrences6h  int             `json:"occurrences_6h"`
	SourceIPs      []string        `json:"source_ips"`
	SourceIPCounts map[string]int  `json:"source_ip_counts"`
	Raw            json.RawMessage `json:"raw"`
}

type Incident struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity"`
	Score       int       `json:"score"`
	AgentID     string    `json:"agent_id,omitempty"`
	AgentLabel  string    `json:"agent_name,omitempty"`
	AgentIP     string    `json:"agent_ip,omitempty"`
	AgentGroups []string  `json:"agent_groups"`
	SourceIP    string    `json:"source_ip,omitempty"`
	RuleLevel   int       `json:"rule_level"`
	Occurrences int       `json:"occurrences"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Feedback    []string  `json:"feedback"`
	Analysis    string    `json:"analysis,omitempty"`
	Alerts      []Alert   `json:"alerts,omitempty"`
}

func NewBackend(cfg Config) (*Backend, error) {
	if len(cfg.Tenants) == 0 {
		return nil, errors.New("au moins un tenant doit être configuré")
	}
	db, err := sql.Open("sqlite", cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("ouvrir la base SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	backend := &Backend{config: cfg, db: db, httpClient: newHTTPClient()}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configurer SQLite: %w", err)
	}
	if err := backend.initializeDatabase(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return backend, nil
}

func (b *Backend) Close() error {
	return b.db.Close()
}

func (b *Backend) WaitBackground() {
	b.workers.Wait()
}

func (b *Backend) initializeDatabase(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS alert_groups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    group_key TEXT NOT NULL,
    wazuh_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_level INTEGER NOT NULL,
    description TEXT NOT NULL,
    agent_id TEXT NOT NULL DEFAULT '',
    agent_name TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    dest_ip TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alert_groups_tenant_last_seen
    ON alert_groups(tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS alert_groups_tenant_key
    ON alert_groups(tenant_id, group_key, last_seen DESC);
CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    group_id TEXT NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    wazuh_id TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_events_group_time
    ON alert_events(group_id, occurred_at DESC);
CREATE TABLE IF NOT EXISTS wazuh_event_dedup (
    tenant_id TEXT NOT NULL,
    wazuh_id TEXT NOT NULL,
    group_id TEXT NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, wazuh_id)
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    agent_id TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    rule_level INTEGER NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    feedback_json TEXT NOT NULL DEFAULT '[]',
    analysis TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS incidents_tenant_updated
    ON incidents(tenant_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    PRIMARY KEY(incident_id, alert_id)
);
CREATE TABLE IF NOT EXISTS incident_ai_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    forced INTEGER NOT NULL DEFAULT 0,
    next_attempt TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS soc_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);`
	if _, err := b.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialiser le schéma SQLite: %w", err)
	}
	var hasForcedColumn bool
	columns, err := b.db.QueryContext(ctx, `PRAGMA table_info(incident_ai_jobs)`)
	if err != nil {
		return fmt.Errorf("vérifier le schéma de la file IA: %w", err)
	}
	for columns.Next() {
		var index, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := columns.Scan(&index, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			columns.Close()
			return fmt.Errorf("lire le schéma de la file IA: %w", err)
		}
		if name == "forced" {
			hasForcedColumn = true
		}
	}
	if err := columns.Err(); err != nil {
		columns.Close()
		return fmt.Errorf("lire le schéma de la file IA: %w", err)
	}
	if err := columns.Close(); err != nil {
		return fmt.Errorf("fermer le schéma de la file IA: %w", err)
	}
	if !hasForcedColumn {
		if _, err := b.db.ExecContext(ctx,
			`ALTER TABLE incident_ai_jobs ADD COLUMN forced INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("mettre à jour le schéma de la file IA: %w", err)
		}
	}
	if _, err := b.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO soc_settings(key, value) VALUES('ai_enabled', 'true')`); err != nil {
		return fmt.Errorf("initialiser les paramètres SOC: %w", err)
	}
	if _, err := b.db.ExecContext(ctx,
		`UPDATE incident_ai_jobs SET status = 'pending' WHERE status = 'processing'`); err != nil {
		return fmt.Errorf("récupérer les analyses interrompues: %w", err)
	}
	return nil
}

type normalizedAlert struct {
	WazuhID     string
	Timestamp   time.Time
	RuleID      string
	RuleLevel   int
	Description string
	AgentID     string
	AgentName   string
	SourceIP    string
	DestIP      string
	Location    string
	RawJSON     string
}

func normalizeAlert(raw map[string]any) (normalizedAlert, error) {
	if raw == nil {
		return normalizedAlert{}, &invalidAlertError{
			err: errors.New("le corps de l'alerte doit être un objet JSON"),
		}
	}
	alert := raw
	if source, ok := raw["_source"].(map[string]any); ok {
		alert = source
	}
	rule := nestedMap(alert, "rule")
	agent := nestedMap(alert, "agent")
	data := nestedMap(alert, "data")
	timestamp := firstString(alert["timestamp"], alert["@timestamp"])
	occurredAt := time.Now().UTC()
	if timestamp != "" {
		parsed, err := parseAlertTimestamp(timestamp)
		if err != nil {
			return normalizedAlert{}, &invalidAlertError{
				err: fmt.Errorf("timestamp doit être une date RFC3339 ou un timestamp Wazuh avec décalage compact: %w", err),
			}
		}
		occurredAt = parsed.UTC()
	}
	rawJSON, err := json.Marshal(alert)
	if err != nil {
		return normalizedAlert{}, fmt.Errorf("encoder l'alerte: %w", err)
	}
	level := intValue(firstValue(rule["level"], alert["level"]))
	if level < 0 {
		level = 0
	}
	if level > 15 {
		level = 15
	}
	return normalizedAlert{
		WazuhID:     firstString(alert["id"], raw["_id"], raw["id"]),
		Timestamp:   occurredAt,
		RuleID:      firstString(rule["id"], alert["rule_id"], "unknown"),
		RuleLevel:   level,
		Description: firstString(rule["description"], alert["description"], "Aucune description"),
		AgentID:     firstString(agent["id"], alert["agent_id"]),
		AgentName:   firstString(agent["name"], alert["agent_name"], "inconnu"),
		SourceIP:    firstString(data["srcip"], data["src_ip"], alert["srcip"]),
		DestIP:      firstString(data["dstip"], data["dst_ip"], alert["dstip"]),
		Location:    firstString(alert["location"]),
		RawJSON:     string(rawJSON),
	}, nil
}

func parseAlertTimestamp(timestamp string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err == nil {
		return parsed, nil
	}
	return time.Parse("2006-01-02T15:04:05.999999999-0700", timestamp)
}

func (b *Backend) IngestAlert(ctx context.Context, tenantID string, raw map[string]any) (Alert, bool, error) {
	event, err := normalizeAlert(raw)
	if err != nil {
		return Alert{}, false, err
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return Alert{}, false, fmt.Errorf("démarrer la transaction d'ingestion: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM wazuh_event_dedup WHERE created_at < ?`,
		formatDatabaseTime(time.Now().Add(-7*24*time.Hour))); err != nil {
		return Alert{}, false, fmt.Errorf("nettoyer les identifiants Wazuh expirés: %w", err)
	}

	groupKey := alertGroupKey(event)
	if event.WazuhID != "" {
		var existingID string
		err := tx.QueryRowContext(ctx,
			`SELECT group_id FROM wazuh_event_dedup WHERE tenant_id = ? AND wazuh_id = ?`,
			tenantID, event.WazuhID).Scan(&existingID)
		if err == nil {
			alert, err := b.loadAlert(ctx, tx, tenantID, existingID)
			if err != nil {
				return Alert{}, false, err
			}
			if err := tx.Commit(); err != nil {
				return Alert{}, false, fmt.Errorf("valider la déduplication Wazuh: %w", err)
			}
			return alert, false, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Alert{}, false, fmt.Errorf("rechercher l'événement Wazuh existant: %w", err)
		}
	}

	now := event.Timestamp
	window := lowAlertWindow
	if event.RuleLevel >= highAlertLevel {
		window = highAlertWindow
	}
	cutoff := formatDatabaseTime(now.Add(-window))
	var groupID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM alert_groups
		 WHERE tenant_id = ? AND group_key = ? AND last_seen >= ?
		 ORDER BY last_seen DESC LIMIT 1`,
		tenantID, groupKey, cutoff).Scan(&groupID)
	if errors.Is(err, sql.ErrNoRows) {
		groupID, err = newID()
		if err != nil {
			return Alert{}, false, err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO alert_groups
			 (id, tenant_id, group_key, wazuh_id, timestamp, rule_id, rule_level,
			  description, agent_id, agent_name, source_ip, dest_ip, location,
			  raw_json, first_seen, last_seen, occurrences)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
			groupID, tenantID, groupKey, event.WazuhID, formatDatabaseTime(event.Timestamp),
			event.RuleID, event.RuleLevel, event.Description, event.AgentID, event.AgentName,
			event.SourceIP, event.DestIP, event.Location, event.RawJSON,
			formatDatabaseTime(event.Timestamp), formatDatabaseTime(event.Timestamp))
	}
	if err != nil {
		return Alert{}, false, fmt.Errorf("créer ou retrouver le groupe d'alertes: %w", err)
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO alert_events(tenant_id, group_id, wazuh_id, occurred_at, source_ip, raw_json)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		tenantID, groupID, event.WazuhID, formatDatabaseTime(event.Timestamp), event.SourceIP, event.RawJSON)
	if err != nil {
		return Alert{}, false, fmt.Errorf("enregistrer l'occurrence de l'alerte: %w", err)
	}
	if event.WazuhID != "" {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO wazuh_event_dedup(tenant_id, wazuh_id, group_id, created_at)
			 VALUES(?, ?, ?, ?)`,
			tenantID, event.WazuhID, groupID, formatDatabaseTime(time.Now())); err != nil {
			return Alert{}, false, fmt.Errorf("lier l'identifiant Wazuh au groupe: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE alert_groups
		 SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?), occurrences = occurrences + 1
		 WHERE id = ?`,
		formatDatabaseTime(event.Timestamp), formatDatabaseTime(event.Timestamp), groupID); err != nil {
		return Alert{}, false, fmt.Errorf("mettre à jour le groupe d'alertes: %w", err)
	}

	group, err := b.loadAlert(ctx, tx, tenantID, groupID)
	if err != nil {
		return Alert{}, false, err
	}
	incidentID, err := b.correlateIncident(ctx, tx, group)
	if err != nil {
		return Alert{}, false, err
	}
	if group.RuleLevel >= highAlertLevel || group.Occurrences6h >= lowAlertAIThreshold {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO incident_ai_jobs(incident_id, next_attempt, created_at)
			 VALUES(?, ?, ?)`,
			incidentID, formatDatabaseTime(time.Now()), formatDatabaseTime(time.Now())); err != nil {
			return Alert{}, false, fmt.Errorf("mettre en file l'analyse automatique: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Alert{}, false, fmt.Errorf("valider l'ingestion de l'alerte: %w", err)
	}
	return group, true, nil
}

func alertGroupKey(event normalizedAlert) string {
	agent := event.AgentID
	if agent == "" {
		agent = event.AgentName
	}
	if agent == "" || agent == "inconnu" {
		agent = event.SourceIP
	}
	digest := sha256.Sum256([]byte(event.RuleID + "\x00" + agent))
	return hex.EncodeToString(digest[:])
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (b *Backend) loadAlert(ctx context.Context, queryer queryer, tenantID, groupID string) (Alert, error) {
	var alert Alert
	var timestamp, firstSeen, lastSeen, raw string
	err := queryer.QueryRowContext(ctx,
		`SELECT id, tenant_id, wazuh_id, timestamp, rule_id, rule_level, description,
		        agent_id, agent_name, source_ip, dest_ip, location, first_seen, last_seen,
		        occurrences, raw_json
		 FROM alert_groups WHERE tenant_id = ? AND id = ?`,
		tenantID, groupID).Scan(
		&alert.ID, &alert.TenantID, &alert.WazuhID, &timestamp, &alert.RuleID, &alert.RuleLevel,
		&alert.Description, &alert.AgentID, &alert.AgentName, &alert.SourceIP, &alert.DestIP,
		&alert.Location, &firstSeen, &lastSeen, &alert.Occurrences, &raw)
	if err != nil {
		return Alert{}, fmt.Errorf("charger le groupe d'alertes: %w", err)
	}
	alert.Timestamp = parseStoredTime(timestamp)
	alert.FirstSeen = parseStoredTime(firstSeen)
	alert.LastSeen = parseStoredTime(lastSeen)
	alert.Raw = json.RawMessage(raw)
	_, alert.AgentIP, alert.AgentGroups, err = agentMetadata(alert.Raw)
	if err != nil {
		return Alert{}, fmt.Errorf("lire les informations de l'agent: %w", err)
	}
	alert.SourceIPCounts = make(map[string]int)
	rows, err := queryer.QueryContext(ctx,
		`SELECT source_ip, COUNT(*) FROM alert_events
		 WHERE group_id = ? AND occurred_at >= ? AND source_ip <> ''
		 GROUP BY source_ip ORDER BY source_ip`,
		groupID, formatDatabaseTime(time.Now().Add(-lowAlertWindow)))
	if err != nil {
		return Alert{}, fmt.Errorf("charger les IP sources du groupe: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			return Alert{}, fmt.Errorf("lire une IP source: %w", err)
		}
		alert.SourceIPCounts[ip] = count
		alert.SourceIPs = append(alert.SourceIPs, ip)
		alert.Occurrences6h += count
	}
	if err := rows.Err(); err != nil {
		return Alert{}, fmt.Errorf("parcourir les IP sources du groupe: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Alert{}, fmt.Errorf("fermer les résultats des IP sources: %w", err)
	}
	if alert.SourceIPs == nil {
		alert.SourceIPs = []string{}
	}
	var count int
	if err := queryer.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alert_events WHERE group_id = ? AND occurred_at >= ?`,
		groupID, formatDatabaseTime(time.Now().Add(-lowAlertWindow))).Scan(&count); err != nil {
		return Alert{}, fmt.Errorf("compter les occurrences récentes: %w", err)
	}
	alert.Occurrences6h = count
	return alert, nil
}

func (b *Backend) correlateIncident(ctx context.Context, tx *sql.Tx, alert Alert) (string, error) {
	now := time.Now().UTC()
	cutoff := formatDatabaseTime(now.Add(-incidentWindow))
	var incidentID string
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM incidents
		 WHERE tenant_id = ? AND status IN ('open', 'investigating') AND updated_at >= ?
		   AND ((? <> '' AND agent_id = ?) OR (? <> '' AND source_ip = ?))
		 ORDER BY updated_at DESC LIMIT 1`,
		alert.TenantID, cutoff, alert.AgentID, alert.AgentID, alert.SourceIP, alert.SourceIP).Scan(&incidentID)
	score := riskScore(alert.RuleLevel, alert.Occurrences6h, alert.RuleID)
	if errors.Is(err, sql.ErrNoRows) {
		incidentID, err = newID()
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO incidents
			 (id, tenant_id, title, status, severity, score, agent_id, source_ip, rule_level,
			  occurrences, created_at, updated_at)
			 VALUES(?, ?, ?, 'open', ?, ?, ?, ?, ?, 1, ?, ?)`,
			incidentID, alert.TenantID, alert.Description, severityFor(score), score,
			alert.AgentID, alert.SourceIP, alert.RuleLevel,
			formatDatabaseTime(now), formatDatabaseTime(now))
		if err != nil {
			return "", fmt.Errorf("créer l'incident corrélé: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("rechercher un incident corrélé: %w", err)
	} else {
		_, err = tx.ExecContext(ctx,
			`UPDATE incidents SET updated_at = ?, occurrences = occurrences + 1,
			 rule_level = MAX(rule_level, ?), score = MAX(score, ?),
			 severity = CASE WHEN ? > score THEN ? ELSE severity END
			 WHERE id = ?`,
			formatDatabaseTime(now), alert.RuleLevel, score, score, severityFor(score), incidentID)
		if err != nil {
			return "", fmt.Errorf("mettre à jour l'incident corrélé: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO incident_alerts(incident_id, alert_id) VALUES(?, ?)`,
		incidentID, alert.ID); err != nil {
		return "", fmt.Errorf("lier le groupe à l'incident: %w", err)
	}
	return incidentID, nil
}

func riskScore(level, occurrences int, ruleID string) int {
	bonus := min(25, max(0, occurrences-1)*5)
	if ruleID == "5710" || ruleID == "5720" || ruleID == "1002" {
		bonus += 10
	}
	return min(100, max(0, level*6+bonus))
}

func severityFor(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func (b *Backend) ListAlerts(ctx context.Context, tenantID string, limit int, since time.Time) ([]Alert, error) {
	query := `SELECT id FROM alert_groups WHERE tenant_id = ?`
	args := []any{tenantID}
	if !since.IsZero() {
		query += ` AND last_seen >= ?`
		args = append(args, formatDatabaseTime(since))
	}
	query += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, limit)
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("lister les groupes d'alertes: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("lire l'identifiant d'alerte: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcourir les groupes d'alertes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("fermer les groupes d'alertes: %w", err)
	}
	alerts := make([]Alert, 0, len(ids))
	for _, id := range ids {
		alert, err := b.loadAlert(ctx, b.db, tenantID, id)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	return alerts, nil
}

func (b *Backend) ListAgentGroups(ctx context.Context, tenantID string) ([]string, error) {
	rows, err := b.db.QueryContext(ctx,
		`SELECT raw_json FROM alert_groups WHERE tenant_id = ? ORDER BY last_seen DESC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("lire les groupes des agents: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]bool)
	groups := make([]string, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("lire une alerte pour ses groupes: %w", err)
		}
		_, _, agentGroups, err := agentMetadata(json.RawMessage(raw))
		if err != nil {
			return nil, fmt.Errorf("extraire les groupes d'un agent: %w", err)
		}
		for _, group := range agentGroups {
			if !seen[group] {
				seen[group] = true
				groups = append(groups, group)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcourir les groupes des agents: %w", err)
	}
	sort.Strings(groups)
	return groups, nil
}

func (b *Backend) ListIncidents(ctx context.Context, tenantID, status string, limit int) ([]Incident, error) {
	query := `SELECT id, tenant_id, title, status, severity, score, agent_id, source_ip,
	                 rule_level, occurrences, created_at, updated_at, feedback_json, analysis,
	                 COALESCE((SELECT ag.agent_name FROM incident_alerts ia
	                           JOIN alert_groups ag ON ag.id = ia.alert_id
	                          WHERE ia.incident_id = i.id
	                          ORDER BY ag.last_seen DESC
	                           LIMIT 1), ''),
	                 COALESCE((SELECT ag.raw_json FROM incident_alerts ia
	                           JOIN alert_groups ag ON ag.id = ia.alert_id
	                          WHERE ia.incident_id = i.id
	                          ORDER BY ag.last_seen DESC
	                           LIMIT 1), '{}')
	          FROM incidents i WHERE i.tenant_id = ?`
	args := []any{tenantID}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("lister les incidents: %w", err)
	}
	defer rows.Close()
	incidents := make([]Incident, 0)
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}
	return incidents, rows.Err()
}

func scanIncident(scanner interface{ Scan(...any) error }) (Incident, error) {
	var incident Incident
	var created, updated, feedback, agentRaw string
	if err := scanner.Scan(
		&incident.ID, &incident.TenantID, &incident.Title, &incident.Status,
		&incident.Severity, &incident.Score, &incident.AgentID, &incident.SourceIP,
		&incident.RuleLevel, &incident.Occurrences, &created, &updated,
		&feedback, &incident.Analysis, &incident.AgentLabel, &agentRaw); err != nil {
		return Incident{}, fmt.Errorf("lire un incident: %w", err)
	}
	incident.CreatedAt = parseStoredTime(created)
	incident.UpdatedAt = parseStoredTime(updated)
	agentName, agentIP, agentGroups, err := agentMetadata(json.RawMessage(agentRaw))
	if err != nil {
		return Incident{}, fmt.Errorf("lire les informations de l'agent de l'incident: %w", err)
	}
	incident.AgentLabel = agentName
	incident.AgentIP = agentIP
	incident.AgentGroups = agentGroups
	if err := json.Unmarshal([]byte(feedback), &incident.Feedback); err != nil {
		return Incident{}, fmt.Errorf("décoder le feedback d'incident: %w", err)
	}
	if incident.Feedback == nil {
		incident.Feedback = []string{}
	}
	return incident, nil
}

func (b *Backend) GetIncident(ctx context.Context, tenantID, id string) (Incident, error) {
	row := b.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, title, status, severity, score, agent_id, source_ip,
		        rule_level, occurrences, created_at, updated_at, feedback_json, analysis,
		        COALESCE((SELECT ag.agent_name FROM incident_alerts ia
		                  JOIN alert_groups ag ON ag.id = ia.alert_id
		                  WHERE ia.incident_id = i.id
		                  ORDER BY ag.last_seen DESC
		                  LIMIT 1), ''),
		        COALESCE((SELECT ag.raw_json FROM incident_alerts ia
		                  JOIN alert_groups ag ON ag.id = ia.alert_id
		                  WHERE ia.incident_id = i.id
		                  ORDER BY ag.last_seen DESC
		                  LIMIT 1), '{}')
		 FROM incidents i WHERE i.tenant_id = ? AND i.id = ?`,
		tenantID, id)
	incident, err := scanIncident(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Incident{}, sql.ErrNoRows
		}
		return Incident{}, err
	}
	rows, err := b.db.QueryContext(ctx,
		`SELECT alert_id FROM incident_alerts WHERE incident_id = ? ORDER BY alert_id`,
		id)
	if err != nil {
		return Incident{}, fmt.Errorf("lister les alertes liées à l'incident: %w", err)
	}
	defer rows.Close()
	alertIDs := make([]string, 0)
	for rows.Next() {
		var alertID string
		if err := rows.Scan(&alertID); err != nil {
			return Incident{}, fmt.Errorf("lire l'alerte liée à l'incident: %w", err)
		}
		alertIDs = append(alertIDs, alertID)
	}
	if err := rows.Err(); err != nil {
		return Incident{}, fmt.Errorf("parcourir les alertes liées à l'incident: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Incident{}, fmt.Errorf("fermer les alertes liées à l'incident: %w", err)
	}
	for _, alertID := range alertIDs {
		alert, err := b.loadAlert(ctx, b.db, tenantID, alertID)
		if err != nil {
			return Incident{}, err
		}
		incident.Alerts = append(incident.Alerts, alert)
	}
	if incident.Alerts == nil {
		incident.Alerts = []Alert{}
	}
	return incident, nil
}

func (b *Backend) UpdateIncident(ctx context.Context, tenantID, id, status, feedback string) (Incident, error) {
	validStatus := map[string]bool{"open": true, "investigating": true, "resolved": true, "false_positive": true}
	if status != "" && !validStatus[status] {
		return Incident{}, errInvalidIncidentStatus
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, fmt.Errorf("démarrer la mise à jour de l'incident: %w", err)
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM incidents WHERE tenant_id = ? AND id = ?`, tenantID, id).Scan(&current); err != nil {
		return Incident{}, err
	}
	if status == "" {
		status = current
	}
	var feedbackJSON string
	if err := tx.QueryRowContext(ctx, `SELECT feedback_json FROM incidents WHERE id = ?`, id).Scan(&feedbackJSON); err != nil {
		return Incident{}, err
	}
	var entries []string
	if err := json.Unmarshal([]byte(feedbackJSON), &entries); err != nil {
		return Incident{}, fmt.Errorf("décoder le feedback existant: %w", err)
	}
	if feedback != "" {
		entries = append(entries, feedback)
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return Incident{}, fmt.Errorf("encoder le feedback: %w", err)
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE incidents SET status = ?, feedback_json = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`,
		status, string(encoded), formatDatabaseTime(time.Now()), tenantID, id)
	if err != nil {
		return Incident{}, fmt.Errorf("mettre à jour l'incident: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Incident{}, fmt.Errorf("valider la mise à jour de l'incident: %w", err)
	}
	return b.GetIncident(ctx, tenantID, id)
}

func (b *Backend) Dashboard(ctx context.Context, tenantID string) (map[string]any, error) {
	result := map[string]any{"alerts": 0, "incidents": 0, "open_incidents": 0, "severity": map[string]int{}}
	for query, key := range map[string]string{
		`SELECT COUNT(*) FROM alert_groups WHERE tenant_id = ?`:                                      "alerts",
		`SELECT COUNT(*) FROM incidents WHERE tenant_id = ?`:                                         "incidents",
		`SELECT COUNT(*) FROM incidents WHERE tenant_id = ? AND status IN ('open', 'investigating')`: "open_incidents",
	} {
		var count int
		if err := b.db.QueryRowContext(ctx, query, tenantID).Scan(&count); err != nil {
			return nil, fmt.Errorf("calculer le tableau de bord: %w", err)
		}
		result[key] = count
	}
	rows, err := b.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM incidents WHERE tenant_id = ? GROUP BY severity`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("calculer les sévérités du tableau de bord: %w", err)
	}
	defer rows.Close()
	severities := result["severity"].(map[string]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("lire la sévérité: %w", err)
		}
		severities[severity] = count
	}
	return result, rows.Err()
}

func (b *Backend) TenantForToken(token string) (string, bool) {
	matchedTenant := ""
	matched := 0
	for configuredToken, tenantID := range b.config.Tenants {
		equal := subtle.ConstantTimeCompare([]byte(configuredToken), []byte(token))
		matched |= equal
		if equal == 1 {
			matchedTenant = tenantID
		}
	}
	return matchedTenant, matched == 1
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		n, _ := typed.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(typed)
		return n
	default:
		return 0
	}
}

func firstValue(values ...any) any {
	for _, value := range values {
		if value != nil && value != "" {
			return value
		}
	}
	return nil
}

func firstString(values ...any) string {
	for _, value := range values {
		if value == nil {
			continue
		}
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}

func nestedMap(value map[string]any, key string) map[string]any {
	if nested, ok := value[key].(map[string]any); ok {
		return nested
	}
	return map[string]any{}
}

func agentMetadata(raw json.RawMessage) (string, string, []string, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", nil, fmt.Errorf("décoder l'alerte Wazuh: %w", err)
	}
	if source, ok := payload["_source"].(map[string]any); ok {
		payload = source
	}
	agent := nestedMap(payload, "agent")
	groups := make([]string, 0)
	labels := nestedMap(agent, "labels")
	groupValue := firstValue(labels["group"], agent["groups"])
	switch value := groupValue.(type) {
	case []any:
		for _, group := range value {
			if name, ok := group.(string); ok && strings.TrimSpace(name) != "" {
				groups = append(groups, name)
			}
		}
	case string:
		if strings.TrimSpace(value) != "" {
			groups = append(groups, value)
		}
	}
	return firstString(agent["name"]), firstString(agent["ip"]), groups, nil
}

func parseStoredTime(raw string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func formatDatabaseTime(value time.Time) string {
	return value.UTC().Format(databaseTimeLayout)
}
