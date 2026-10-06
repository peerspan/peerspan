package person

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func serveAgent(t *testing.T, keys ...ed25519.PrivateKey) {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", socket)
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func checkSigns(t *testing.T, s Signer, want ed25519.PublicKey) {
	t.Helper()
	defer s.Close()
	if !s.PublicKey().Equal(want) {
		t.Fatal("wrong person key")
	}
	sig, err := membership.SignSSHSIG(s, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if err = membership.VerifySSHSIG(want, []byte("hello"), sig); err != nil {
		t.Fatal(err)
	}
}

func TestAgentSigning(t *testing.T) {
	key := newKey(t)
	serveAgent(t, key)
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	checkSigns(t, s, key.Public().(ed25519.PublicKey))
}

func TestAgentNeedsExactlyOneIdentityUnlessSelected(t *testing.T) {
	first, second := newKey(t), newKey(t)
	serveAgent(t, first, second)
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "several") {
		t.Fatalf("ambiguous agent: %v", err)
	}
	// A public key file selects one identity in the agent.
	public, err := ssh.NewPublicKey(second.Public())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id.pub")
	if err = os.WriteFile(path, ssh.MarshalAuthorizedKey(public), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	checkSigns(t, s, second.Public().(ed25519.PublicKey))
	if got, err := ParsePublicKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))); err != nil || !got.Equal(second.Public().(ed25519.PublicKey)) {
		t.Fatalf("parse public key line: %v", err)
	}
}

func TestKeyFileFallbackWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := Load(""); err == nil {
		t.Fatal("no agent and no key file accepted")
	}
	key := newKey(t)
	block, err := ssh.MarshalPrivateKey(key, "person")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err = os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	checkSigns(t, s, key.Public().(ed25519.PublicKey))
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(key, "person", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, pem.EncodeToMemory(encrypted), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("encrypted key file accepted without an agent")
	}
}
