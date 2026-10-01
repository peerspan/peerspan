package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
)

const minSecretBytes = 8

// PutSecret writes a secret value on the host, outside any capsule workspace.
func (s Store) PutSecret(name, value string) error {
	if !capsule.ValidID(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	if len(value) < minSecretBytes {
		return fmt.Errorf("secret value must be at least %d bytes", minSecretBytes)
	}
	dir := filepath.Join(s.Dir, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600)
}

// SecretPath returns the host file for a secret that has been stored.
func (s Store) SecretPath(name string) (string, error) {
	if !capsule.ValidID(name) {
		return "", fmt.Errorf("invalid secret name %q", name)
	}
	path := filepath.Join(s.Dir, "secrets", name)
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("secret %q not found", name)
	}
	return path, nil
}

// ListSecrets returns stored secret names.
func (s Store) ListSecrets() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, "secrets"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !capsule.ValidID(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}
