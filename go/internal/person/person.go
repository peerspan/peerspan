// Package person loads a person's OpenSSH ssh-ed25519 key for the CLI: from
// ssh-agent by default, or from an OpenSSH key file. Daemons never use it.
package person

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Identity is what `person show` prints.
type Identity struct {
	PersonID     string `json:"person_id"`
	PublicKey    string `json:"public_key"`
	SSHPublicKey string `json:"ssh_public_key"`
}

func IdentityOf(key ed25519.PublicKey) Identity {
	return Identity{PersonID: membership.PersonID(key), PublicKey: membership.EncodeKey(key), SSHPublicKey: membership.SSHAuthorizedKey(key)}
}

// agentSigner signs through ssh-agent; the private key never leaves it.
type agentSigner struct {
	client agent.ExtendedAgent
	conn   net.Conn
	key    ssh.PublicKey
	public ed25519.PublicKey
}

func (a *agentSigner) PublicKey() ed25519.PublicKey { return a.public }
func (a *agentSigner) Sign(data []byte) ([]byte, error) {
	sig, err := a.client.Sign(a.key, data)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent refused to sign: %w", err)
	}
	if sig.Format != ssh.KeyAlgoED25519 || len(sig.Blob) != ed25519.SignatureSize {
		return nil, errors.New("ssh-agent returned a non-Ed25519 signature")
	}
	return sig.Blob, nil
}
func (a *agentSigner) Close() error { return a.conn.Close() }

// Signer is a membership.PersonSigner that may hold an agent connection.
type Signer interface {
	membership.PersonSigner
	Close() error
}

type fileSigner struct{ membership.KeySigner }

func (fileSigner) Close() error { return nil }

func ed25519Of(key ssh.PublicKey) (ed25519.PublicKey, bool) {
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, false
	}
	// Agent identities (*agent.Key) carry only the wire encoding; parse it.
	crypto, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		parsed, err := ssh.ParsePublicKey(key.Marshal())
		if crypto, ok = parsed.(ssh.CryptoPublicKey); err != nil || !ok {
			return nil, false
		}
	}
	public, ok := crypto.CryptoPublicKey().(ed25519.PublicKey)
	return public, ok
}

// ParsePublicKey reads an `ssh-ed25519 AAAA…` line, or a path to a file
// containing one, and returns the raw key.
func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	text := []byte(value)
	if !strings.HasPrefix(strings.TrimSpace(value), "ssh-") {
		data, err := os.ReadFile(value)
		if err != nil {
			return nil, fmt.Errorf("person public key must be an ssh-ed25519 line or a path to one: %w", err)
		}
		text = data
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("invalid SSH public key: %w", err)
	}
	public, ok := ed25519Of(key)
	if !ok {
		return nil, errors.New("person keys must be ssh-ed25519")
	}
	return public, nil
}

// Load returns the person signer. With no path it uses the only ssh-ed25519
// identity in the agent at SSH_AUTH_SOCK. A path to a public key selects that
// identity in the agent; a path to an unencrypted OpenSSH private key signs
// locally without an agent.
func Load(path string) (Signer, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if raw, err := ssh.ParseRawPrivateKey(data); err == nil {
			key, ok := raw.(*ed25519.PrivateKey)
			if !ok {
				return nil, errors.New("person keys must be ssh-ed25519")
			}
			return fileSigner{membership.KeySigner{Key: *key}}, nil
		} else if strings.Contains(string(data), "PRIVATE KEY") {
			return nil, fmt.Errorf("cannot use person key file (encrypted keys must be loaded into ssh-agent): %w", err)
		}
		public, err := ParsePublicKey(path)
		if err != nil {
			return nil, err
		}
		return fromAgent(public)
	}
	return fromAgent(nil)
}

// LoadKey returns the signer for one key in the agent, for keys the CLI
// recognizes rather than discovers, such as a network's current SSH root.
func LoadKey(want ed25519.PublicKey) (Signer, error) { return fromAgent(want) }

func fromAgent(want ed25519.PublicKey) (Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, errors.New("no ssh-agent: SSH_AUTH_SOCK is not set; use --person-key PATH")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("cannot reach ssh-agent: %w", err)
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("cannot list ssh-agent identities: %w", err)
	}
	var found []*agentSigner
	for _, k := range keys {
		public, ok := ed25519Of(k)
		if !ok || (want != nil && !public.Equal(want)) {
			continue
		}
		found = append(found, &agentSigner{client: client, conn: conn, key: k, public: public})
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0 && want != nil:
		conn.Close()
		return nil, errors.New("that person key is not loaded in ssh-agent")
	case len(found) == 0:
		conn.Close()
		return nil, errors.New("ssh-agent has no ssh-ed25519 identity; add one or use --person-key PATH")
	default:
		conn.Close()
		return nil, errors.New("ssh-agent has several ssh-ed25519 identities; choose one with --person-key PATH")
	}
}
