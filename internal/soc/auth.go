package soc

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	passwordIterations   = 600_000
	adminSessionLifetime = 8 * time.Hour
)

type adminSession struct {
	Username  string
	Role      string
	TenantID  string
	ExpiresAt time.Time
}

type adminIdentity struct {
	Username string
	Role     string
}

type adminIdentityContextKey struct{}

type Account struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type invalidAccountError struct {
	message string
}

func (e *invalidAccountError) Error() string {
	return e.message
}

var errLastAdminAccount = errors.New("impossible de supprimer le dernier compte administrateur")
var errInvalidCurrentPassword = errors.New("ancien mot de passe incorrect")
var errInitialAdminAlreadyConfigured = errors.New("le compte administrateur initial est déjà configuré")

func (b *Backend) initializeAccounts(ctx context.Context) error {
	_, err := b.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS soc_accounts (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("créer la table des comptes: %w", err)
	}
	return nil
}

func (b *Backend) adminSetupRequired(ctx context.Context) (bool, error) {
	var count int
	if err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM soc_accounts`).Scan(&count); err != nil {
		return false, fmt.Errorf("compter les comptes: %w", err)
	}
	if count == 0 {
		return true, nil
	}
	var passwordHash string
	err := b.db.QueryRowContext(ctx,
		`SELECT password_hash FROM soc_accounts WHERE username = 'admin' AND role = 'admin'`).
		Scan(&passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("vérifier le compte admin initial: %w", err)
	}
	return verifyPassword("admin", passwordHash), nil
}

func (b *Backend) setupInitialAdmin(ctx context.Context, username, password string) error {
	if !validAccountUsername(username) {
		return &invalidAccountError{message: "l’identifiant doit contenir 3 à 64 caractères : lettres, chiffres, point, tiret ou souligné"}
	}
	if utf8.RuneCountInString(password) < 12 {
		return &invalidAccountError{message: "le mot de passe doit contenir au moins 12 caractères"}
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("initialiser le mot de passe admin: %w", err)
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("démarrer la configuration du compte admin: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM soc_accounts`).Scan(&count); err != nil {
		return fmt.Errorf("vérifier la configuration initiale: %w", err)
	}
	if count == 0 {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO soc_accounts(username, password_hash, role) VALUES(?, ?, 'admin')`,
			username, passwordHash); err != nil {
			return fmt.Errorf("créer le compte admin initial: %w", err)
		}
	} else {
		var legacyHash string
		err := tx.QueryRowContext(ctx,
			`SELECT password_hash FROM soc_accounts WHERE username = 'admin' AND role = 'admin'`).
			Scan(&legacyHash)
		if errors.Is(err, sql.ErrNoRows) {
			return errInitialAdminAlreadyConfigured
		}
		if err != nil {
			return fmt.Errorf("vérifier le compte admin initial: %w", err)
		}
		if !verifyPassword("admin", legacyHash) {
			return errInitialAdminAlreadyConfigured
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE soc_accounts SET username = ?, password_hash = ? WHERE username = 'admin' AND password_hash = ?`,
			username, passwordHash, legacyHash); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return &invalidAccountError{message: "cet identifiant existe déjà"}
			}
			return fmt.Errorf("remplacer le compte admin par défaut: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("valider la configuration initiale: %w", err)
	}
	return nil
}

func (b *Backend) initializeWazuhConfiguration(ctx context.Context) error {
	var raw string
	err := b.db.QueryRowContext(ctx,
		`SELECT value FROM soc_settings WHERE key = 'wazuh_sources'`).Scan(&raw)
	if err == nil {
		sources, migrated, err := b.decodeWazuhSources(raw)
		if err != nil {
			return fmt.Errorf("déchiffrer les identifiants Wazuh sauvegardés: %w", err)
		}
		if migrated {
			encoded, err := b.encodeWazuhSources(sources)
			if err != nil {
				return fmt.Errorf("encoder la configuration Wazuh migrée: %w", err)
			}
			if _, err := b.db.ExecContext(ctx,
				`UPDATE soc_settings SET value = ? WHERE key = 'wazuh_sources'`, string(encoded)); err != nil {
				return fmt.Errorf("enregistrer la configuration Wazuh chiffrée: %w", err)
			}
		}
		b.config.WazuhSources = sources
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("lire la configuration Wazuh sauvegardée: %w", err)
	}
	if b.config.WazuhSources == nil {
		b.config.WazuhSources = []WazuhSource{}
	}
	encoded, err := b.encodeWazuhSources(b.config.WazuhSources)
	if err != nil {
		return fmt.Errorf("chiffrer la configuration Wazuh initiale: %w", err)
	}
	if _, err := b.db.ExecContext(ctx,
		`INSERT INTO soc_settings(key, value) VALUES('wazuh_sources', ?)`, string(encoded)); err != nil {
		return fmt.Errorf("sauvegarder la configuration Wazuh initiale: %w", err)
	}
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("générer le sel du mot de passe: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		return "", fmt.Errorf("dériver le mot de passe: %w", err)
	}
	return strconv.Itoa(passwordIterations) + ":" + hex.EncodeToString(salt) + ":" + hex.EncodeToString(key), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 3 {
		return false
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations < 1 || iterations > 2_000_000 {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := hex.DecodeString(parts[2])
	if err != nil || len(expected) != 32 {
		return false
	}
	actual, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	return err == nil && subtle.ConstantTimeCompare(actual, expected) == 1
}

func (b *Backend) verifyAdminPassword(ctx context.Context, username, password string) (bool, error) {
	var passwordHash string
	err := b.db.QueryRowContext(ctx,
		`SELECT password_hash FROM soc_accounts WHERE username = ? AND role = 'admin'`,
		username).Scan(&passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lire le mot de passe administrateur: %w", err)
	}
	return verifyPassword(password, passwordHash), nil
}

func (b *Backend) login(username, password string) (string, time.Time, error) {
	var encodedHash string
	var role string
	err := b.db.QueryRow(`SELECT password_hash, role FROM soc_accounts WHERE username = ?`, username).
		Scan(&encodedHash, &role)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !verifyPassword(password, encodedHash)) {
		return "", time.Time{}, errInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("vérifier le compte: %w", err)
	}
	if role != "admin" {
		return "", time.Time{}, errInvalidCredentials
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("générer la session: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(adminSessionLifetime)
	tenantIDs := b.tenantIDs()
	if len(tenantIDs) == 0 {
		return "", time.Time{}, errors.New("aucun tenant configuré")
	}
	tenantID := tenantIDs[0]
	if sources := b.wazuhSources(); len(sources) > 0 {
		tenantID = sources[0].TenantID
	}
	b.sessionMu.Lock()
	for existingToken, session := range b.sessions {
		if time.Now().After(session.ExpiresAt) {
			delete(b.sessions, existingToken)
		}
	}
	b.sessions[token] = adminSession{Username: username, Role: role, TenantID: tenantID, ExpiresAt: expiresAt}
	b.sessionMu.Unlock()
	return token, expiresAt, nil
}

var errInvalidCredentials = errors.New("identifiant ou mot de passe invalide")

func (b *Backend) sessionForToken(token string) (adminSession, bool) {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	session, exists := b.sessions[token]
	if !exists {
		return adminSession{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(b.sessions, token)
		return adminSession{}, false
	}
	return session, true
}

func (b *Backend) revokeSession(token string) {
	b.sessionMu.Lock()
	delete(b.sessions, token)
	b.sessionMu.Unlock()
}

func (b *Backend) tenantIDs() []string {
	tenants := make(map[string]struct{})
	for _, tenantID := range b.config.TenantIDs {
		tenants[tenantID] = struct{}{}
	}
	for _, tenantID := range b.config.Tenants {
		tenants[tenantID] = struct{}{}
	}
	result := make([]string, 0, len(tenants))
	for tenantID := range tenants {
		result = append(result, tenantID)
	}
	sort.Strings(result)
	return result
}

func (b *Backend) createAccount(username, password string) error {
	if !validAccountUsername(username) {
		return &invalidAccountError{message: "l’identifiant doit contenir 3 à 64 caractères : lettres, chiffres, point, tiret ou souligné"}
	}
	if utf8.RuneCountInString(password) < 12 {
		return &invalidAccountError{message: "le mot de passe doit contenir au moins 12 caractères"}
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}
	if _, err := b.db.Exec(`INSERT INTO soc_accounts(username, password_hash, role) VALUES(?, ?, 'admin')`,
		username, passwordHash); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return &invalidAccountError{message: "cet identifiant existe déjà"}
		}
		return fmt.Errorf("créer le compte: %w", err)
	}
	return nil
}

func validAccountUsername(username string) bool {
	if len(username) < 3 || len(username) > 64 {
		return false
	}
	for _, character := range username {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '.' && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func (b *Backend) listAccounts() ([]Account, error) {
	rows, err := b.db.Query(`SELECT username, role FROM soc_accounts ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("lire les comptes: %w", err)
	}
	defer rows.Close()
	accounts := make([]Account, 0)
	for rows.Next() {
		var account Account
		if err := rows.Scan(&account.Username, &account.Role); err != nil {
			return nil, fmt.Errorf("lire un compte: %w", err)
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (b *Backend) deleteAccount(username string) error {
	tx, err := b.db.Begin()
	if err != nil {
		return fmt.Errorf("démarrer la suppression du compte: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM soc_accounts WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("supprimer le compte: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("vérifier la suppression du compte: %w", err)
	}
	if changed == 0 {
		return sql.ErrNoRows
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM soc_accounts WHERE role = 'admin'`).Scan(&count); err != nil {
		return fmt.Errorf("vérifier le dernier compte admin: %w", err)
	}
	if count == 0 {
		return errLastAdminAccount
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("valider la suppression du compte: %w", err)
	}
	b.sessionMu.Lock()
	for token, session := range b.sessions {
		if session.Username == username {
			delete(b.sessions, token)
		}
	}
	b.sessionMu.Unlock()
	return nil
}

func (b *Backend) changePassword(username, currentPassword, newPassword string) error {
	var currentHash string
	if err := b.db.QueryRow(`SELECT password_hash FROM soc_accounts WHERE username = ?`, username).
		Scan(&currentHash); err != nil {
		return fmt.Errorf("lire le mot de passe du compte: %w", err)
	}
	if !verifyPassword(currentPassword, currentHash) {
		return errInvalidCurrentPassword
	}
	if utf8.RuneCountInString(newPassword) < 12 {
		return &invalidAccountError{message: "le mot de passe doit contenir au moins 12 caractères"}
	}
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	result, err := b.db.Exec(`UPDATE soc_accounts SET password_hash = ? WHERE username = ? AND password_hash = ?`,
		passwordHash, username, currentHash)
	if err != nil {
		return fmt.Errorf("modifier le mot de passe: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("vérifier la modification du mot de passe: %w", err)
	}
	if changed == 0 {
		return sql.ErrNoRows
	}
	b.sessionMu.Lock()
	for token, session := range b.sessions {
		if session.Username == username {
			delete(b.sessions, token)
		}
	}
	b.sessionMu.Unlock()
	return nil
}

func (b *Backend) setWazuhSources(ctx context.Context, sources []WazuhSource) error {
	encoded, err := b.encodeWazuhSources(sources)
	if err != nil {
		return fmt.Errorf("chiffrer et encoder les identifiants Wazuh: %w", err)
	}
	if _, err := b.db.ExecContext(ctx,
		`INSERT INTO soc_settings(key, value) VALUES('wazuh_sources', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(encoded)); err != nil {
		return fmt.Errorf("sauvegarder la configuration Wazuh: %w", err)
	}
	b.wazuhConfigMu.Lock()
	b.config.WazuhSources = append([]WazuhSource(nil), sources...)
	b.wazuhConfigMu.Unlock()
	if len(sources) > 0 {
		b.sessionMu.Lock()
		for token, session := range b.sessions {
			session.TenantID = sources[0].TenantID
			b.sessions[token] = session
		}
		b.sessionMu.Unlock()
	}
	b.collectorMu.Lock()
	select {
	case b.collectorUpdates <- append([]WazuhSource(nil), sources...):
	default:
		select {
		case <-b.collectorUpdates:
		default:
		}
		b.collectorUpdates <- append([]WazuhSource(nil), sources...)
	}
	b.collectorMu.Unlock()
	return nil
}

func (b *Backend) loginHandler(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := b.adminSetupRequired(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if setupRequired {
		writeError(w, http.StatusForbidden, "terminez la configuration initiale avant de vous connecter")
		return
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, expiresAt, err := b.login(payload.Username, payload.Password)
	if errors.Is(err, errInvalidCredentials) {
		writeError(w, http.StatusUnauthorized, errInvalidCredentials.Error())
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": expiresAt})
}

func (b *Backend) setupStatusHandler(w http.ResponseWriter, r *http.Request) {
	required, err := b.adminSetupRequired(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{"required": required})
}

func (b *Backend) setupAdminHandler(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRemoteAddr(r.RemoteAddr) &&
		!isSetupAllowedRemoteAddr(r.RemoteAddr, b.config.SetupAllowedIP) {
		writeError(w, http.StatusForbidden, "la configuration initiale doit être effectuée depuis le serveur ou l'adresse IP autorisée")
		return
	}
	var payload struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := decodeBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if payload.Password != payload.ConfirmPassword {
		writeError(w, http.StatusBadRequest, "les deux mots de passe ne correspondent pas")
		return
	}
	if err := b.setupInitialAdmin(r.Context(), payload.Username, payload.Password); err != nil {
		if errors.Is(err, errInitialAdminAlreadyConfigured) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		var validationError *invalidAccountError
		if errors.As(err, &validationError) {
			writeError(w, http.StatusBadRequest, validationError.Error())
		} else {
			writeInternalError(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (b *Backend) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := r.Context().Value(adminIdentityContextKey{}).(adminIdentity)
		if !ok || identity.Role != "admin" {
			writeError(w, http.StatusForbidden, "accès réservé aux administrateurs")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (b *Backend) accountsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		accounts, err := b.listAccounts()
		if err != nil {
			writeInternalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, accounts)
	case http.MethodPost:
		var payload struct {
			Username        string `json:"username"`
			Password        string `json:"password"`
			ConfirmPassword string `json:"confirm_password"`
		}
		if err := decodeBody(w, r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if payload.Password != payload.ConfirmPassword {
			writeError(w, http.StatusBadRequest, "les deux mots de passe ne correspondent pas")
			return
		}
		if err := b.createAccount(payload.Username, payload.Password); err != nil {
			var validationError *invalidAccountError
			if errors.As(err, &validationError) {
				writeError(w, http.StatusBadRequest, validationError.Error())
			} else {
				writeInternalError(w, err)
			}
			return
		}
		writeJSON(w, http.StatusCreated, map[string]bool{"created": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "méthode non autorisée")
	}
}

func (b *Backend) deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	identity := r.Context().Value(adminIdentityContextKey{}).(adminIdentity)
	if identity.Username == username {
		writeError(w, http.StatusBadRequest, "utilisez un autre compte pour supprimer ce compte")
		return
	}
	if err := b.deleteAccount(username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "compte introuvable")
			return
		}
		if errors.Is(err, errLastAdminAccount) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		CurrentPassword    string `json:"current_password"`
		NewPassword        string `json:"new_password"`
		ConfirmNewPassword string `json:"confirm_new_password"`
	}
	if err := decodeBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if payload.NewPassword != payload.ConfirmNewPassword {
		writeError(w, http.StatusBadRequest, "les deux nouveaux mots de passe ne correspondent pas")
		return
	}
	identity := r.Context().Value(adminIdentityContextKey{}).(adminIdentity)
	if err := b.changePassword(identity.Username, payload.CurrentPassword, payload.NewPassword); err != nil {
		if errors.Is(err, errInvalidCurrentPassword) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		var validationError *invalidAccountError
		if errors.As(err, &validationError) {
			writeError(w, http.StatusBadRequest, validationError.Error())
		} else {
			writeInternalError(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) wazuhConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sources := b.wazuhSources()
		if len(sources) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"configured": false})
			return
		}
		source := sources[0]
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true, "url": source.URL,
			"username": source.Username, "verify_tls": source.VerifyTLS,
			"alerts_index":          source.AlertsIndex,
			"agents_index":          source.AgentsIndex,
			"vulnerabilities_index": source.VulnerabilitiesIndex,
			"batch_size":            source.BatchSize,
			"password_configured":   source.Password != "",
		})
		return
	}
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "méthode non autorisée")
		return
	}
	var payload struct {
		URL                  string `json:"url"`
		Username             string `json:"username"`
		Password             string `json:"password"`
		VerifyTLS            *bool  `json:"verify_tls"`
		AlertsIndex          string `json:"alerts_index"`
		AgentsIndex          string `json:"agents_index"`
		VulnerabilitiesIndex string `json:"vulnerabilities_index"`
		BatchSize            int    `json:"batch_size"`
	}
	if err := decodeBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var source WazuhSource
	sources := b.wazuhSources()
	if len(sources) > 0 {
		source = sources[0]
	} else {
		tenantIDs := b.tenantIDs()
		if len(tenantIDs) == 0 {
			writeError(w, http.StatusInternalServerError, "aucun tenant configuré")
			return
		}
		source.TenantID = tenantIDs[0]
	}
	if payload.Password == "" && source.Password != "" &&
		source.URL == payload.URL && source.Username == payload.Username {
		payload.Password = source.Password
	}
	source = WazuhSource{
		TenantID: source.TenantID, URL: strings.TrimSpace(payload.URL),
		Username: strings.TrimSpace(payload.Username), Password: payload.Password,
		VerifyTLS: payload.VerifyTLS, AlertsIndex: strings.TrimSpace(payload.AlertsIndex),
		AgentsIndex:          strings.TrimSpace(payload.AgentsIndex),
		VulnerabilitiesIndex: strings.TrimSpace(payload.VulnerabilitiesIndex),
		BatchSize:            payload.BatchSize,
	}
	if source.AlertsIndex == "" {
		source.AlertsIndex = "wazuh-alerts-*"
	}
	if source.AgentsIndex == "" {
		source.AgentsIndex = defaultAgentsIndex
	}
	if source.VulnerabilitiesIndex == "" {
		source.VulnerabilitiesIndex = defaultVulnerabilitiesIndex
	}
	if source.BatchSize == 0 {
		source.BatchSize = 100
	}
	if source.VerifyTLS == nil {
		verify := true
		source.VerifyTLS = &verify
	}
	if err := validateWazuhSource(source); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if source.Password != "" && len(b.credentialKey) != 32 {
		writeError(w, http.StatusServiceUnavailable, errCredentialKeyRequired.Error())
		return
	}
	if err := b.pollWazuh(r.Context(), source); err != nil {
		writeError(w, http.StatusBadGateway, wazuhConfigurationFailure(err))
		return
	}
	if err := b.checkWazuhVulnerabilityIndex(r.Context(), source); err != nil {
		writeError(w, http.StatusBadGateway,
			"Vérification de l’index des vulnérabilités impossible : "+wazuhConfigurationFailure(err))
		return
	}
	if err := b.checkWazuhAgentsIndex(r.Context(), source); err != nil {
		writeError(w, http.StatusBadGateway,
			"Vérification de l’index des agents impossible : "+wazuhConfigurationFailure(err))
		return
	}
	if err := b.setWazuhSources(r.Context(), []WazuhSource{source}); err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
}

func wazuhConfigurationFailure(err error) string {
	var responseError *wazuhHTTPError
	if !errors.As(err, &responseError) {
		return fmt.Sprintf("Test de connexion Wazuh impossible : %v", err)
	}
	message := fmt.Sprintf("Wazuh Indexer a répondu HTTP %d", responseError.statusCode)
	switch responseError.statusCode {
	case http.StatusUnauthorized:
		message = "Wazuh Indexer a refusé l’authentification (HTTP 401)"
	case http.StatusForbidden:
		message = "Wazuh Indexer a refusé l’accès (HTTP 403) ; vérifiez les droits de lecture"
	case http.StatusNotFound:
		message = "Wazuh Indexer n’a pas trouvé la ressource (HTTP 404) ; vérifiez l’index configuré"
	}
	if responseError.body != "" {
		message += ". Détail : " + responseError.body
	}
	return message
}

func (b *Backend) clearWazuhConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	if err := b.setWazuhSources(r.Context(), []WazuhSource{}); err != nil {
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validateWazuhSource(source WazuhSource) error {
	if source.TenantID == "" {
		return errors.New("aucun tenant interne n’est disponible")
	}
	if source.URL == "" || source.Username == "" || source.Password == "" {
		return errors.New("l’URL, l’utilisateur et le mot de passe sont obligatoires")
	}
	if err := validateURL(source.URL, false); err != nil {
		return fmt.Errorf("URL Wazuh invalide: %w", err)
	}
	if source.BatchSize < 1 || source.BatchSize > 1000 {
		return errors.New("la taille de lot doit être comprise entre 1 et 1000")
	}
	return nil
}

func bearerToken(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

func (b *Backend) logoutHandler(w http.ResponseWriter, r *http.Request) {
	b.revokeSession(bearerToken(r))
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) currentAccountHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := r.Context().Value(adminIdentityContextKey{}).(adminIdentity)
	if !ok {
		writeError(w, http.StatusUnauthorized, "connexion par compte requise")
		return
	}
	writeJSON(w, http.StatusOK, Account{Username: identity.Username, Role: identity.Role})
}

func (b *Backend) authenticateAdminRequest(next http.Handler) http.Handler {
	return b.authenticate(b.adminOnly(next))
}

func setAdminIdentity(ctx context.Context, username, role string) context.Context {
	return context.WithValue(ctx, adminIdentityContextKey{}, adminIdentity{Username: username, Role: role})
}
