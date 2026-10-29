package soc

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host              string
	Port              int
	DatabasePath      string
	Tenants           map[string]string
	GeneratedToken    string
	TokenFilePath     string
	OllamaURL         string
	OllamaModel       string
	IrisBaseURL       string
	IrisAPIKey        string
	IrisCaseID        int64
	WazuhSources      []WazuhSource
	WazuhPollInterval time.Duration
}

type WazuhSource struct {
	TenantID    string `json:"tenant_id"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	VerifyTLS   *bool  `json:"verify_tls"`
	AlertsIndex string `json:"alerts_index"`
	BatchSize   int    `json:"batch_size"`
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Host:              envOr("SOC_HOST", "0.0.0.0"),
		Port:              8080,
		DatabasePath:      envOr("SOC_DB_PATH", "soc.db"),
		TokenFilePath:     envOr("SOC_API_TOKEN_FILE", ".soc-api-token"),
		OllamaURL:         strings.TrimRight(envOr("OLLAMA_URL", "http://127.0.0.1:11434"), "/"),
		OllamaModel:       envOr("OLLAMA_MODEL", "llama3.1"),
		IrisBaseURL:       strings.TrimRight(os.Getenv("IRIS_BASE_URL"), "/"),
		IrisAPIKey:        os.Getenv("IRIS_API_KEY"),
		WazuhPollInterval: 60 * time.Second,
	}
	if err := validateURL(cfg.OllamaURL, false); err != nil {
		return Config{}, fmt.Errorf("OLLAMA_URL invalide: %w", err)
	}

	port, err := strconv.Atoi(envOr("SOC_PORT", "8080"))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("SOC_PORT doit être un port compris entre 1 et 65535")
	}
	cfg.Port = port

	if os.Getenv("SOC_TENANTS_JSON") == "" {
		token, err := loadOrCreateAPIToken(cfg.TokenFilePath)
		if err != nil {
			return Config{}, fmt.Errorf("créer ou lire le jeton API: %w", err)
		}
		cfg.GeneratedToken = token
		cfg.Tenants = map[string]string{token: "client-a"}
	} else {
		if err := decodeEnvJSON("SOC_TENANTS_JSON", &cfg.Tenants, map[string]string{}); err != nil {
			return Config{}, err
		}
		if len(cfg.Tenants) == 0 {
			return Config{}, errors.New("SOC_TENANTS_JSON doit contenir au moins un jeton et un client")
		}
	}
	for token, tenant := range cfg.Tenants {
		if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) ||
			strings.TrimSpace(tenant) == "" {
			return Config{}, errors.New("les jetons et identifiants clients ne peuvent pas être vides")
		}
	}
	if err := decodeEnvJSON("WAZUH_SOURCES_JSON", &cfg.WazuhSources, []WazuhSource{}); err != nil {
		return Config{}, err
	}
	for i := range cfg.WazuhSources {
		source := &cfg.WazuhSources[i]
		if source.TenantID == "" || source.URL == "" || source.Username == "" || source.Password == "" {
			return Config{}, fmt.Errorf("WAZUH_SOURCES_JSON[%d] doit définir tenant_id, url, username et password", i)
		}
		if !tenantExists(cfg.Tenants, source.TenantID) {
			return Config{}, fmt.Errorf("WAZUH_SOURCES_JSON[%d] référence un tenant non configuré", i)
		}
		if source.AlertsIndex == "" {
			source.AlertsIndex = "wazuh-alerts-*"
		}
		if source.BatchSize <= 0 || source.BatchSize > 1000 {
			source.BatchSize = 100
		}
		if source.VerifyTLS == nil {
			verify := true
			source.VerifyTLS = &verify
		}
		if err := validateURL(source.URL, false); err != nil {
			return Config{}, fmt.Errorf("URL Wazuh invalide: %w", err)
		}
	}

	seconds, err := strconv.Atoi(envOr("WAZUH_POLL_SECONDS", "60"))
	if err != nil || seconds < 15 {
		return Config{}, errors.New("WAZUH_POLL_SECONDS doit être supérieur ou égal à 15")
	}
	cfg.WazuhPollInterval = time.Duration(seconds) * time.Second

	caseID := os.Getenv("IRIS_CASE_ID")
	if caseID != "" {
		cfg.IrisCaseID, err = strconv.ParseInt(caseID, 10, 64)
		if err != nil || cfg.IrisCaseID <= 0 {
			return Config{}, errors.New("IRIS_CASE_ID doit être un entier positif")
		}
	}
	irisConfigured := []bool{cfg.IrisBaseURL != "", cfg.IrisAPIKey != "", cfg.IrisCaseID > 0}
	configuredCount := 0
	for _, configured := range irisConfigured {
		if configured {
			configuredCount++
		}
	}
	if configuredCount != 0 && configuredCount != len(irisConfigured) {
		return Config{}, errors.New("configurez ensemble IRIS_BASE_URL, IRIS_API_KEY et IRIS_CASE_ID")
	}
	if cfg.IrisBaseURL != "" {
		if err := validateURL(cfg.IrisBaseURL, true); err != nil {
			return Config{}, fmt.Errorf("IRIS_BASE_URL invalide: %w", err)
		}
	}
	return cfg, nil
}

func decodeEnvJSON[T any](name string, destination *T, fallback T) error {
	raw := os.Getenv(name)
	if raw == "" {
		*destination = fallback
		return nil
	}
	if err := json.Unmarshal([]byte(raw), destination); err != nil {
		return fmt.Errorf("%s doit contenir du JSON valide: %w", name, err)
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func validateURL(raw string, requireHTTPS bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("une origine HTTP(S) valide est requise")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("l'URL doit être une origine sans chemin")
	}
	if parsed.Scheme != "https" && (requireHTTPS || parsed.Scheme != "http") {
		return errors.New("HTTPS est requis")
	}
	return nil
}

func tenantExists(tenants map[string]string, tenantID string) bool {
	for _, id := range tenants {
		if id == tenantID {
			return true
		}
	}
	return false
}

func loadOrCreateAPIToken(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		token, generateErr := generateAPIToken()
		if generateErr != nil {
			file.Close()
			os.Remove(path)
			return "", generateErr
		}
		if _, err := io.WriteString(file, token+"\n"); err != nil {
			file.Close()
			os.Remove(path)
			return "", fmt.Errorf("enregistrer le jeton dans %q: %w", path, err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return "", fmt.Errorf("synchroniser le jeton dans %q: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return "", fmt.Errorf("fermer le fichier du jeton %q: %w", path, err)
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("créer le fichier %q: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("lire le fichier %q: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if !validAPIToken(token) {
		return "", fmt.Errorf("le fichier %q doit contenir un jeton alphanumérique de 20 caractères; supprimez-le serveur arrêté pour en générer un nouveau", path)
	}
	return token, nil
}

func generateAPIToken() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const sampleSpace = 256
	const acceptedByteLimit = sampleSpace - sampleSpace%len(alphabet)
	token := make([]byte, 20)
	randomBytes := make([]byte, 64)
	tokenIndex := 0
	for tokenIndex < len(token) {
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("générer les caractères du jeton: %w", err)
		}
		for _, value := range randomBytes {
			if int(value) >= acceptedByteLimit {
				continue
			}
			token[tokenIndex] = alphabet[int(value)%len(alphabet)]
			tokenIndex++
			if tokenIndex == len(token) {
				break
			}
		}
	}
	return string(token), nil
}

func validAPIToken(token string) bool {
	if len(token) != 20 {
		return false
	}
	for _, character := range token {
		if !('a' <= character && character <= 'z') &&
			!('A' <= character && character <= 'Z') &&
			!('0' <= character && character <= '9') {
			return false
		}
	}
	return true
}
