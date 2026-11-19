package soc

import (
	"os"
	"path/filepath"
	"testing"
)

func loadConfigWithEnv(t *testing.T, tenantConfig string) Config {
	t.Helper()
	t.Setenv("SOC_HOST", "")
	t.Setenv("SOC_PORT", "")
	t.Setenv("SOC_DB_PATH", "")
	t.Setenv("SOC_TLS_CERT_FILE", "")
	t.Setenv("SOC_TLS_KEY_FILE", "")
	t.Setenv("SOC_CREDENTIAL_KEY_FILE", "")
	t.Setenv("SOC_SETUP_ALLOWED_IP", "")
	t.Setenv("SOC_TENANTS_JSON", tenantConfig)
	t.Setenv("OLLAMA_URL", "")
	t.Setenv("OLLAMA_MODEL", "")
	t.Setenv("WAZUH_SOURCES_JSON", "")
	t.Setenv("WAZUH_POLL_SECONDS", "")
	t.Setenv("IRIS_BASE_URL", "")
	t.Setenv("IRIS_API_KEY", "")
	t.Setenv("IRIS_CASE_ID", "")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestLoadConfigUsesDefaultTenantWithoutGeneratingAPIToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "api-token")
	t.Setenv("SOC_API_TOKEN_FILE", tokenFile)
	config := loadConfigWithEnv(t, "")
	if config.Host != "127.0.0.1" {
		t.Fatalf("default host = %q, want 127.0.0.1", config.Host)
	}
	if len(config.Tenants) != 0 {
		t.Fatalf("default API tokens = %#v, want none", config.Tenants)
	}
	if !tenantExists(config, "client-a") {
		t.Fatal("default client-a tenant is missing")
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatalf("API token file should not be generated; stat error = %v", err)
	}
}

func TestLoadConfigKeepsExplicitTenantTokens(t *testing.T) {
	config := loadConfigWithEnv(t, `{"my-existing-token":"tenant-a"}`)
	if config.Tenants["my-existing-token"] != "tenant-a" {
		t.Fatalf("explicit token mapping = %#v", config.Tenants)
	}
	if !tenantExists(config, "tenant-a") {
		t.Fatal("tenant associated with the explicit API token is missing")
	}
}

func TestLoadConfigReadsCredentialKeyFile(t *testing.T) {
	loadConfigWithEnv(t, "")
	keyFile := filepath.Join(t.TempDir(), "wazuh.key")
	t.Setenv("SOC_CREDENTIAL_KEY_FILE", keyFile)
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.CredentialKeyFile != keyFile {
		t.Fatalf("credential key file = %q, want %q", config.CredentialKeyFile, keyFile)
	}
}

func TestLoadConfigRequiresTLSForRemoteBind(t *testing.T) {
	loadConfigWithEnv(t, `{"token-a":"tenant-a"}`)
	t.Setenv("SOC_HOST", "0.0.0.0")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected remote HTTP bind to require TLS")
	}

	t.Setenv("SOC_TLS_CERT_FILE", filepath.Join(t.TempDir(), "server.crt"))
	t.Setenv("SOC_TLS_KEY_FILE", filepath.Join(t.TempDir(), "server.key"))
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "0.0.0.0" {
		t.Fatalf("configured host = %q, want 0.0.0.0", config.Host)
	}
}

func TestLoadConfigRequiresTLSCertificateAndKeyTogether(t *testing.T) {
	loadConfigWithEnv(t, `{"token-a":"tenant-a"}`)
	t.Setenv("SOC_TLS_CERT_FILE", filepath.Join(t.TempDir(), "server.crt"))
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected unpaired TLS certificate to be rejected")
	}
}

func TestLoadConfigValidatesSetupAllowedIP(t *testing.T) {
	loadConfigWithEnv(t, "")
	t.Setenv("SOC_SETUP_ALLOWED_IP", "203.0.113.10")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.SetupAllowedIP != "203.0.113.10" {
		t.Fatalf("setup allowed IP = %q, want 203.0.113.10", config.SetupAllowedIP)
	}

	t.Setenv("SOC_SETUP_ALLOWED_IP", "not-an-ip")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected invalid setup allowed IP to be rejected")
	}
}
