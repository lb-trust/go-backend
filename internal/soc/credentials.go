package soc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

const wazuhPasswordCipherAAD = "wazuh-password:v1"
const wazuhManagerAPIPasswordCipherAAD = "wazuh-manager-api-password:v1"

var errCredentialKeyRequired = errors.New("clé de chiffrement Wazuh indisponible ou invalide ; lancez le service avec start.sh ou définissez SOC_CREDENTIAL_KEY_FILE")

type storedWazuhSource struct {
	TenantID                    string `json:"tenant_id"`
	URL                         string `json:"url"`
	Username                    string `json:"username"`
	Password                    string `json:"password"`
	PasswordEncrypted           bool   `json:"password_encrypted,omitempty"`
	VerifyTLS                   *bool  `json:"verify_tls,omitempty"`
	ManagerAPIURL               string `json:"manager_api_url,omitempty"`
	ManagerAPIUsername          string `json:"manager_api_username,omitempty"`
	ManagerAPIPassword          string `json:"manager_api_password,omitempty"`
	ManagerAPIPasswordEncrypted bool   `json:"manager_api_password_encrypted,omitempty"`
	ManagerAPIVerifyTLS         *bool  `json:"manager_api_verify_tls,omitempty"`
	AlertsIndex                 string `json:"alerts_index,omitempty"`
	VulnerabilitiesIndex        string `json:"vulnerabilities_index,omitempty"`
	BatchSize                   int    `json:"batch_size,omitempty"`
}

func loadCredentialKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("lire SOC_CREDENTIAL_KEY_FILE: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("SOC_CREDENTIAL_KEY_FILE doit désigner un fichier ordinaire")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("SOC_CREDENTIAL_KEY_FILE doit être lisible uniquement par le compte du service")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lire la clé de chiffrement des identifiants: %w", err)
	}
	if len(key) != 32 {
		return nil, errCredentialKeyRequired
	}
	return key, nil
}

func (b *Backend) encodeWazuhSources(sources []WazuhSource) ([]byte, error) {
	encodedSources := make([]storedWazuhSource, len(sources))
	for i, source := range sources {
		encodedSources[i] = storedWazuhSource{
			TenantID: source.TenantID, URL: source.URL, Username: source.Username,
			Password: source.Password, VerifyTLS: source.VerifyTLS,
			ManagerAPIURL: source.ManagerAPIURL, ManagerAPIUsername: source.ManagerAPIUsername,
			ManagerAPIPassword: source.ManagerAPIPassword, ManagerAPIVerifyTLS: source.ManagerAPIVerifyTLS,
			AlertsIndex: source.AlertsIndex, VulnerabilitiesIndex: source.VulnerabilitiesIndex,
			BatchSize: source.BatchSize,
		}
		if source.Password != "" {
			password, err := b.encryptCredential(source.Password)
			if err != nil {
				return nil, err
			}
			encodedSources[i].Password = password
			encodedSources[i].PasswordEncrypted = true
		}
		if source.ManagerAPIPassword != "" {
			password, err := b.encryptCredentialWithAAD(source.ManagerAPIPassword, wazuhManagerAPIPasswordCipherAAD)
			if err != nil {
				return nil, err
			}
			encodedSources[i].ManagerAPIPassword = password
			encodedSources[i].ManagerAPIPasswordEncrypted = true
		}
	}
	return json.Marshal(encodedSources)
}

func (b *Backend) decodeWazuhSources(raw string) ([]WazuhSource, bool, error) {
	var encodedSources []storedWazuhSource
	if err := json.Unmarshal([]byte(raw), &encodedSources); err != nil {
		return nil, false, err
	}
	sources := make([]WazuhSource, len(encodedSources))
	migrated := false
	for i, encoded := range encodedSources {
		source := WazuhSource{
			TenantID: encoded.TenantID, URL: encoded.URL, Username: encoded.Username,
			Password: encoded.Password, VerifyTLS: encoded.VerifyTLS,
			ManagerAPIURL: encoded.ManagerAPIURL, ManagerAPIUsername: encoded.ManagerAPIUsername,
			ManagerAPIPassword: encoded.ManagerAPIPassword, ManagerAPIVerifyTLS: encoded.ManagerAPIVerifyTLS,
			AlertsIndex: encoded.AlertsIndex, VulnerabilitiesIndex: encoded.VulnerabilitiesIndex,
			BatchSize: encoded.BatchSize,
		}
		if source.VulnerabilitiesIndex == "" {
			source.VulnerabilitiesIndex = defaultVulnerabilitiesIndex
		}
		if encoded.PasswordEncrypted {
			password, err := b.decryptCredential(encoded.Password)
			if err != nil {
				return nil, false, err
			}
			source.Password = password
		} else if encoded.Password != "" {
			migrated = true
		}
		if encoded.ManagerAPIPasswordEncrypted {
			password, err := b.decryptCredentialWithAAD(encoded.ManagerAPIPassword, wazuhManagerAPIPasswordCipherAAD)
			if err != nil {
				return nil, false, err
			}
			source.ManagerAPIPassword = password
		} else if encoded.ManagerAPIPassword != "" {
			migrated = true
		}
		sources[i] = source
	}
	return sources, migrated, nil
}

func (b *Backend) encryptCredential(plaintext string) (string, error) {
	return b.encryptCredentialWithAAD(plaintext, wazuhPasswordCipherAAD)
}

func (b *Backend) encryptCredentialWithAAD(plaintext, aad string) (string, error) {
	if len(b.credentialKey) != 32 {
		return "", errCredentialKeyRequired
	}
	block, err := aes.NewCipher(b.credentialKey)
	if err != nil {
		return "", fmt.Errorf("initialiser le chiffrement des identifiants: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialiser le chiffrement authentifié: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("générer le nonce de chiffrement: %w", err)
	}
	encrypted := aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return base64.RawStdEncoding.EncodeToString(encrypted), nil
}

func (b *Backend) decryptCredential(encoded string) (string, error) {
	return b.decryptCredentialWithAAD(encoded, wazuhPasswordCipherAAD)
}

func (b *Backend) decryptCredentialWithAAD(encoded, aad string) (string, error) {
	if len(b.credentialKey) != 32 {
		return "", errCredentialKeyRequired
	}
	encrypted, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("le mot de passe Wazuh chiffré est invalide")
	}
	block, err := aes.NewCipher(b.credentialKey)
	if err != nil {
		return "", fmt.Errorf("initialiser le déchiffrement des identifiants: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialiser le déchiffrement authentifié: %w", err)
	}
	if len(encrypted) < aead.NonceSize() {
		return "", errors.New("le mot de passe Wazuh chiffré est incomplet")
	}
	nonce, ciphertext := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return "", errors.New("impossible de déchiffrer le mot de passe Wazuh ; vérifiez SOC_CREDENTIAL_KEY_FILE")
	}
	return string(plaintext), nil
}
