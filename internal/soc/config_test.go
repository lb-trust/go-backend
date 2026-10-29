package soc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func loadConfigWithEnv(t *testing.T, tokenFile, tenantConfig string) Config {
	t.Helper()
	t.Setenv("SOC_HOST", "")
	t.Setenv("SOC_PORT", "")
	t.Setenv("SOC_DB_PATH", "")
	t.Setenv("SOC_API_TOKEN_FILE", tokenFile)
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

func TestLoadConfigGeneratesAndReusesAPIToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "api-token")
	first := loadConfigWithEnv(t, tokenFile, "")
	if first.Host != "0.0.0.0" {
		t.Fatalf("default host = %q, want 0.0.0.0", first.Host)
	}
	if !validAPIToken(first.GeneratedToken) {
		t.Fatalf("generated token has an invalid shape: %q", first.GeneratedToken)
	}
	if first.Tenants[first.GeneratedToken] != "client-a" {
		t.Fatalf("generated token is not assigned to client-a")
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("token file permissions are too open: %o", info.Mode().Perm())
	}

	second := loadConfigWithEnv(t, tokenFile, "")
	if second.GeneratedToken != first.GeneratedToken {
		t.Fatalf("token changed between restarts: %q != %q", second.GeneratedToken, first.GeneratedToken)
	}
}

func TestLoadConfigKeepsExplicitTenantTokens(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "api-token")
	config := loadConfigWithEnv(t, tokenFile, `{"my-existing-token":"tenant-a"}`)
	if config.GeneratedToken != "" {
		t.Fatal("explicitly configured tenant token should not be replaced")
	}
	if config.Tenants["my-existing-token"] != "tenant-a" {
		t.Fatalf("explicit token mapping = %#v", config.Tenants)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatalf("automatic token file should not be created; stat error = %v", err)
	}
}

func TestLoadConfigRejectsInvalidSavedToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "api-token")
	if err := os.WriteFile(tokenFile, []byte("too-short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOC_HOST", "")
	t.Setenv("SOC_PORT", "")
	t.Setenv("SOC_DB_PATH", "")
	t.Setenv("SOC_API_TOKEN_FILE", tokenFile)
	t.Setenv("OLLAMA_URL", "")
	t.Setenv("OLLAMA_MODEL", "")
	t.Setenv("WAZUH_SOURCES_JSON", "")
	t.Setenv("WAZUH_POLL_SECONDS", "")
	t.Setenv("IRIS_BASE_URL", "")
	t.Setenv("IRIS_API_KEY", "")
	t.Setenv("IRIS_CASE_ID", "")
	t.Setenv("SOC_TENANTS_JSON", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected invalid saved token to be rejected")
	}
}
