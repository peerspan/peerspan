package control

import (
	"fmt"
	"os"
	"strings"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/secret"
)

// SetSecret stores a secret value on the host.
func (s Service) SetSecret(name, value string) error {
	return s.Store.PutSecret(name, value)
}

// ListSecrets returns stored secret names.
func (s Service) ListSecrets() ([]string, error) {
	return s.Store.ListSecrets()
}

func (s Service) secretMounts(names []string) ([]runtime.Secret, error) {
	seen := map[string]bool{}
	var mounts []runtime.Secret
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("secret %q is repeated", name)
		}
		seen[name] = true
		path, err := s.Store.SecretPath(name)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, runtime.Secret{Name: name, HostPath: path})
	}
	return mounts, nil
}

func (s Service) secretValues(names []string) ([]string, error) {
	var values []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		path, err := s.Store.SecretPath(name)
		if err != nil {
			return nil, err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		values = append(values, string(body))
	}
	return values, nil
}

func redactArgv(argv, values []string) []string {
	out := make([]string, len(argv))
	for i, arg := range argv {
		out[i] = secret.Redact(arg, values)
	}
	return out
}
