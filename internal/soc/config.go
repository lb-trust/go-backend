package soc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	CredentialKeyFile string
	Tenants           map[string]string
	TenantIDs         []string
	TLSCertFile       string
	TLSKeyFile        string
	SetupAllowedIP    string
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
		Host:              envOr("SOC_HOST", "127.0.0.1"),
		Port:              8080,
		DatabasePath:      envOr("SOC_DB_PATH", "soc.db"),
		CredentialKeyFile: os.Getenv("SOC_CREDENTIAL_KEY_FILE"),
		TLSCertFile:       os.Getenv("SOC_TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("SOC_TLS_KEY_FILE"),
		SetupAllowedIP:    os.Getenv("SOC_SETUP_ALLOWED_IP"),
		Tenants:           make(map[string]string),
		TenantIDs:         []string{"client-a"},
		OllamaURL:         strings.TrimRight(envOr("OLLAMA_URL", "http://127.0.0.1:11434"), "/"),
		OllamaModel:       envOr("OLLAMA_MODEL", "llama3.1"),
		IrisBaseURL:       strings.TrimRight(os.Getenv("IRIS_BASE_URL"), "/"),
		IrisAPIKey:        os.Getenv("IRIS_API_KEY"),
		WazuhPollInterval: 60 * time.Second,
	}
	if err := validateURL(cfg.OllamaURL, false); err != nil {
		return Config{}, fmt.Errorf("OLLAMA_URL invalide: %w", err)
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, errors.New("SOC_TLS_CERT_FILE et SOC_TLS_KEY_FILE doivent être définis ensemble")
	}
	if !isLoopbackHost(cfg.Host) && cfg.TLSCertFile == "" {
		return Config{}, errors.New("une écoute réseau non locale exige SOC_TLS_CERT_FILE et SOC_TLS_KEY_FILE")
	}
	if cfg.SetupAllowedIP != "" && net.ParseIP(cfg.SetupAllowedIP) == nil {
		return Config{}, errors.New("SOC_SETUP_ALLOWED_IP doit être une adresse IP valide")
	}

	port, err := strconv.Atoi(envOr("SOC_PORT", "8080"))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("SOC_PORT doit être un port compris entre 1 et 65535")
	}
	cfg.Port = port

	if os.Getenv("SOC_TENANTS_JSON") != "" {
		if err := decodeEnvJSON("SOC_TENANTS_JSON", &cfg.Tenants, map[string]string{}); err != nil {
			return Config{}, err
		}
		if len(cfg.Tenants) == 0 {
			return Config{}, errors.New("SOC_TENANTS_JSON doit contenir au moins un jeton et un client")
		}
		cfg.TenantIDs = cfg.TenantIDs[:0]
	}
	for token, tenant := range cfg.Tenants {
		if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) ||
			strings.TrimSpace(tenant) == "" {
			return Config{}, errors.New("les jetons et identifiants clients ne peuvent pas être vides")
		}
		cfg.TenantIDs = append(cfg.TenantIDs, tenant)
	}
	cfg.TenantIDs = uniqueStrings(cfg.TenantIDs)
	if err := decodeEnvJSON("WAZUH_SOURCES_JSON", &cfg.WazuhSources, []WazuhSource{}); err != nil {
		return Config{}, err
	}
	for i := range cfg.WazuhSources {
		source := &cfg.WazuhSources[i]
		if source.TenantID == "" || source.URL == "" || source.Username == "" || source.Password == "" {
			return Config{}, fmt.Errorf("WAZUH_SOURCES_JSON[%d] doit définir tenant_id, url, username et password", i)
		}
		if !tenantExists(cfg, source.TenantID) {
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

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	return err == nil && isLoopbackHost(host)
}

func isSetupAllowedRemoteAddr(remoteAddr, allowedIP string) bool {
	if allowedIP == "" {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	remoteIP := net.ParseIP(host)
	configuredIP := net.ParseIP(allowedIP)
	return remoteIP != nil && configuredIP != nil && remoteIP.Equal(configuredIP)
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

func tenantExists(config Config, tenantID string) bool {
	for _, id := range config.TenantIDs {
		if id == tenantID {
			return true
		}
	}
	for _, id := range config.Tenants {
		if id == tenantID {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
