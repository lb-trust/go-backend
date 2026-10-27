package soc

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type AIJob struct {
	IncidentID string    `json:"incident_id"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	Attempts   int       `json:"attempts"`
	Forced     bool      `json:"forced"`
	CreatedAt  time.Time `json:"created_at"`
}

type AIControl struct {
	Enabled bool    `json:"enabled"`
	Queue   []AIJob `json:"queue"`
}

var errAIJobInProgress = errors.New("une analyse de cet incident est déjà en cours")

func (b *Backend) AIControl(ctx context.Context, tenantID string) (AIControl, error) {
	var enabledValue string
	if err := b.db.QueryRowContext(ctx,
		`SELECT value FROM soc_settings WHERE key = 'ai_enabled'`).Scan(&enabledValue); err != nil {
		return AIControl{}, fmt.Errorf("lire le réglage de la file IA: %w", err)
	}
	rows, err := b.db.QueryContext(ctx,
		`SELECT j.incident_id, i.title, i.severity, j.status, j.attempts, j.forced, j.created_at
		 FROM incident_ai_jobs j
		 JOIN incidents i ON i.id = j.incident_id
		 WHERE i.tenant_id = ?
		 ORDER BY CASE j.status
		            WHEN 'processing' THEN 0
		            WHEN 'pending' THEN 1
		            WHEN 'failed' THEN 2
		            ELSE 3
		          END, j.created_at DESC
		 LIMIT 100`,
		tenantID)
	if err != nil {
		return AIControl{}, fmt.Errorf("charger la file IA: %w", err)
	}
	defer rows.Close()
	control := AIControl{Enabled: enabledValue == "true", Queue: make([]AIJob, 0)}
	for rows.Next() {
		var job AIJob
		var createdAt string
		var forced int
		if err := rows.Scan(&job.IncidentID, &job.Title, &job.Severity,
			&job.Status, &job.Attempts, &forced, &createdAt); err != nil {
			return AIControl{}, fmt.Errorf("lire une tâche de la file IA: %w", err)
		}
		job.Forced = forced != 0
		job.CreatedAt = parseStoredTime(createdAt)
		control.Queue = append(control.Queue, job)
	}
	if err := rows.Err(); err != nil {
		return AIControl{}, fmt.Errorf("parcourir la file IA: %w", err)
	}
	return control, nil
}

func (b *Backend) SetAIEnabled(ctx context.Context, enabled bool) error {
	value := "false"
	if enabled {
		value = "true"
	}
	if _, err := b.db.ExecContext(ctx,
		`UPDATE soc_settings SET value = ? WHERE key = 'ai_enabled'`, value); err != nil {
		return fmt.Errorf("modifier le réglage de la file IA: %w", err)
	}
	return nil
}

func (b *Backend) AIEnabled(ctx context.Context) (bool, error) {
	var value string
	if err := b.db.QueryRowContext(ctx,
		`SELECT value FROM soc_settings WHERE key = 'ai_enabled'`).Scan(&value); err != nil {
		return false, fmt.Errorf("lire le réglage de la file IA: %w", err)
	}
	return value == "true", nil
}

func (b *Backend) QueueIncidentAnalysis(ctx context.Context, tenantID, incidentID string) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("démarrer la mise en file de l'analyse: %w", err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM incidents WHERE tenant_id = ? AND id = ?`,
		tenantID, incidentID).Scan(&exists); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO incident_ai_jobs(incident_id, status, attempts, forced, next_attempt, created_at)
		 VALUES(?, 'pending', 0, 1, ?, ?)
		 ON CONFLICT(incident_id) DO UPDATE SET
		   status = 'pending', attempts = 0, forced = 1, next_attempt = excluded.next_attempt,
		   created_at = excluded.created_at
		 WHERE incident_ai_jobs.status <> 'processing'`,
		incidentID, formatDatabaseTime(time.Now()), formatDatabaseTime(time.Now()))
	if err != nil {
		return fmt.Errorf("mettre l'incident en file d'analyse: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("vérifier la mise en file d'analyse: %w", err)
	}
	if changed == 0 {
		return errAIJobInProgress
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE incidents SET analysis = '' WHERE tenant_id = ? AND id = ?`,
		tenantID, incidentID); err != nil {
		return fmt.Errorf("préparer une nouvelle analyse: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("valider la mise en file d'analyse: %w", err)
	}
	return nil
}
