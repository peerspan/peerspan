package coord

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func id(k ed25519.PrivateKey) string { return membership.HostID(k.Public().(ed25519.PublicKey)) }

func TestRegistrationJoinAndSync(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "coord"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	root, creator, joiner, other := key(t), key(t), key(t), key(t)
	now := membership.Timestamp(time.Now())
	self, _ := membership.Invite(root, "creator", now)
	selfProof, _ := self.Join(creator, now)
	register := registerRequest{Name: "team", RootPublicKey: self.RootPublicKey, Membership: selfProof, Address: "127.0.0.1:7000"}
	if _, _, err = s.register(ctx, id(joiner), register); !errors.Is(err, errForbidden) {
		t.Fatalf("registration for another host: %v", err)
	}
	if status, m, err := s.register(ctx, id(creator), register); err != nil || status != http.StatusCreated || len(m.Members) != 1 {
		t.Fatalf("register: %d %v", status, err)
	}
	if status, _, err := s.register(ctx, id(creator), register); err != nil || status != http.StatusOK {
		t.Fatalf("repeat register: %d %v", status, err)
	}
	invite, _ := membership.Invite(root, "joiner", membership.Timestamp(time.Now().Add(time.Hour)))
	proof, _ := invite.Join(joiner, now)
	network := invite.NetworkID
	if _, _, err = s.join(ctx, id(joiner), "net_"+strings.Repeat("0", 64), joinRequest{Membership: proof}); !errors.Is(err, errNotFound) {
		t.Fatalf("unknown network: %v", err)
	}
	if _, err = s.sync(ctx, id(joiner), network, ""); !errors.Is(err, errForbidden) {
		t.Fatalf("non-member sync: %v", err)
	}
	if status, m, err := s.join(ctx, id(joiner), network, joinRequest{Membership: proof}); err != nil || status != http.StatusCreated || len(m.Members) != 2 {
		t.Fatalf("join: %d %v", status, err)
	}
	retry, _ := invite.Join(joiner, membership.Timestamp(time.Now().Add(time.Second)))
	status, m, err := s.join(ctx, id(joiner), network, joinRequest{Membership: retry})
	if err != nil || status != http.StatusOK || !strings.Contains(string(m.Members[0].Membership)+string(m.Members[1].Membership), proof.JoinedAt) {
		t.Fatalf("idempotent join: %d %v", status, err)
	}
	reuse, _ := invite.Join(other, now)
	if _, _, err = s.join(ctx, id(other), network, joinRequest{Membership: reuse}); !errors.Is(err, errConflict) {
		t.Fatalf("invite reuse: %v", err)
	}
	expiredInvite, _ := membership.Invite(root, "late", membership.Timestamp(time.Now().Add(-time.Minute)))
	late, _ := expiredInvite.Join(other, membership.Timestamp(time.Now().Add(-2*time.Minute)))
	if _, _, err = s.join(ctx, id(other), network, joinRequest{Membership: late}); !errors.Is(err, errForbidden) {
		t.Fatalf("expired invite: %v", err)
	}
	tampered := reuse
	tampered.Member = "mallory"
	if _, _, err = s.join(ctx, id(other), network, joinRequest{Membership: tampered}); !errors.Is(err, membership.ErrInvalid) {
		t.Fatalf("tampered chain: %v", err)
	}
	if m, err := s.sync(ctx, id(joiner), network, "10.0.0.2:7001"); err != nil || m.Members[0].Address+m.Members[1].Address == "127.0.0.1:7000" {
		t.Fatalf("sync: %v", err)
	}
	if _, err = s.sync(ctx, id(joiner), network, "host:1"); !errors.Is(err, errInvalid) {
		t.Fatalf("invalid address: %v", err)
	}
	identity := s.Identity()
	s.Close()
	if read, err := ReadIdentity(ctx, filepath.Join(filepath.Dir(s.lock.Name()))); err != nil || read != identity {
		t.Fatalf("read identity: %+v %v", read, err)
	}
	reopened, err := Open(ctx, filepath.Dir(s.lock.Name()))
	if err != nil || reopened.Identity() != identity {
		t.Fatalf("identity changed on reopen: %v", err)
	}
	reopened.Close()
}

func TestHTTPRequiresClientKeyAndStrictJSON(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "coord"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = Open(ctx, filepath.Dir(s.lock.Name())); err == nil {
		t.Fatal("second process opened locked state")
	}
	server := httptest.NewUnstartedServer(s.Handler())
	server.TLS, err = s.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	client := func(withCert bool) *http.Client {
		config := tlsid.Config()
		config.InsecureSkipVerify = true
		if withCert {
			cert, _ := tlsid.Certificate(key(t), "host", time.Now())
			config.Certificates = []tls.Certificate{cert}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
	}
	if _, err = client(false).Post(server.URL+"/coord/v1/networks/x/sync", "application/json", strings.NewReader(`{"address":""}`)); err == nil {
		t.Fatal("client without a certificate connected")
	}
	for body, want := range map[string]int{
		`{"address":""}`:              http.StatusForbidden,
		`{"address":null}`:            http.StatusBadRequest,
		`{"address":"","extra":1}`:    http.StatusBadRequest,
		`{}`:                          http.StatusBadRequest,
		`{"address":""} {}`:           http.StatusBadRequest,
		`{"address":"127.0.0.1:0"}`:   http.StatusBadRequest,
		`{"address":"127.0.0.1:1"} x`: http.StatusBadRequest,
	} {
		response, err := client(true).Post(server.URL+"/coord/v1/networks/net_x/sync", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Errorf("%s: got %d, want %d", body, response.StatusCode, want)
		}
	}
}
