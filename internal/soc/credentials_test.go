package soc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadCredentialKeyValidatesLengthAndPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "wazuh.key")
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCredentialKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != string(key) {
		t.Fatal("loaded credential key differs from the file")
	}

	if err := os.WriteFile(path, key[:31], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentialKey(path); err == nil {
		t.Fatal("expected an invalid key length to be rejected")
	}

	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, key, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentialKey(path); err == nil {
			t.Fatal("expected a key readable by other users to be rejected")
		}
	}
}
