package person

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// The generated key (launch slice 3): when network create or join finds no
// person key, the CLI generates one at $XDG_CONFIG_HOME/capsule/person_ed25519.
// It is the only person key a daemon reads, to renew policies.

// Key sources reported as person.key.source.
const (
	SourceOption    = "option"
	SourceGenerated = "generated"
	SourceAgent     = "agent"
	SourceNew       = "new"
)

// GeneratedKeyPath is $XDG_CONFIG_HOME/capsule/person_ed25519, by default
// under ~/.config.
func GeneratedKeyPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "capsule", "person_ed25519"), nil
}

// LoadPrivateFile loads an unencrypted OpenSSH ssh-ed25519 private key file.
func LoadPrivateFile(path string) (Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("cannot use person key file %s: %w", path, err)
	}
	key, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("person keys must be ssh-ed25519")
	}
	return fileSigner{membership.KeySigner{Key: *key}}, nil
}

// Choice is the person key create and join use, and where it came from.
// A new key exists only in memory until Save.
type Choice struct {
	Signer
	Source string
	// Path is the key file, or "" for an agent key.
	Path string
	key  ed25519.PrivateKey
}

// Choose picks the person key: --person-key (option), the generated key
// if it exists, the only ssh-ed25519 identity in ssh-agent, or else a new
// key. Several agent identities and no generated key is an error.
func Choose(option string) (*Choice, error) {
	if option != "" {
		s, err := Load(option)
		if err != nil {
			return nil, err
		}
		path, _ := filepath.Abs(option)
		return &Choice{Signer: s, Source: SourceOption, Path: path}, nil
	}
	generated, err := GeneratedKeyPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(generated); err == nil {
		s, err := LoadPrivateFile(generated)
		if err != nil {
			return nil, err
		}
		return &Choice{Signer: s, Source: SourceGenerated, Path: generated}, nil
	}
	if s, err := soleAgentKey(); err != nil || s != nil {
		if err != nil {
			return nil, err
		}
		return &Choice{Signer: s, Source: SourceAgent}, nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Choice{Signer: fileSigner{membership.KeySigner{Key: key}}, Source: SourceNew, Path: generated, key: key}, nil
}

// soleAgentKey is the only ssh-ed25519 identity in ssh-agent, nil when there
// is no reachable agent or it holds none, and an error listing them when it
// holds several.
func soleAgentKey() (Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		conn.Close()
		return nil, nil
	}
	var found []*agentSigner
	var listed []string
	for _, k := range keys {
		public, ok := ed25519Of(k)
		if !ok {
			continue
		}
		found = append(found, &agentSigner{client: client, conn: conn, key: k, public: public})
		listed = append(listed, fmt.Sprintf("%q %s", k.Comment, ssh.FingerprintSHA256(k)))
	}
	switch len(found) {
	case 0:
		conn.Close()
		return nil, nil
	case 1:
		return found[0], nil
	}
	conn.Close()
	return nil, fmt.Errorf("ssh-agent has several ssh-ed25519 identities (%s); choose one with --person-key PATH", strings.Join(listed, ", "))
}

// Save writes a new key to its path: the private key mode 0600 and the
// public key beside it mode 0644, in a 0700 directory. It never overwrites.
// Other sources have nothing to save.
func (c *Choice) Save(comment string) error {
	if c.Source != SourceNew || c.key == nil {
		return nil
	}
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(c.key, comment)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(c.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(pem.EncodeToMemory(block))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(c.Path)
		return err
	}
	public, err := ssh.NewPublicKey(c.key.Public())
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " " + comment + "\n"
	pub, err := os.OpenFile(c.Path+".pub", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = pub.WriteString(line)
	if closeErr := pub.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(c.Path+".pub", 0o644)
	}
	return err
}
