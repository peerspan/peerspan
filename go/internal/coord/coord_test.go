package coord

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/tlsid"
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
	register := registerRequest{Name: "team", RootPublicKey: self.RootPublicKey, Membership: selfProof, Address: "127.0.0.1:7000", Candidates: []string{"203.0.113.10:7000"}}
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
	if _, _, err = s.join(ctx, id(joiner), "net_"+strings.Repeat("0", 64), joinRequest{Membership: proof, Candidates: []string{}}); !errors.Is(err, errNotFound) {
		t.Fatalf("unknown network: %v", err)
	}
	if _, err = s.sync(ctx, id(joiner), network, "", []string{}); !errors.Is(err, errForbidden) {
		t.Fatalf("non-member sync: %v", err)
	}
	if status, m, err := s.join(ctx, id(joiner), network, joinRequest{Membership: proof, Candidates: []string{}}); err != nil || status != http.StatusCreated || len(m.Members) != 2 {
		t.Fatalf("join: %d %v", status, err)
	}
	retry, _ := invite.Join(joiner, membership.Timestamp(time.Now().Add(time.Second)))
	status, m, err := s.join(ctx, id(joiner), network, joinRequest{Membership: retry, Candidates: []string{}})
	if err != nil || status != http.StatusOK || !strings.Contains(string(m.Members[0].Membership)+string(m.Members[1].Membership), proof.JoinedAt) {
		t.Fatalf("idempotent join: %d %v", status, err)
	}
	reuse, _ := invite.Join(other, now)
	if _, _, err = s.join(ctx, id(other), network, joinRequest{Membership: reuse, Candidates: []string{}}); !errors.Is(err, errConflict) {
		t.Fatalf("invite reuse: %v", err)
	}
	expiredInvite, _ := membership.Invite(root, "late", membership.Timestamp(time.Now().Add(-time.Minute)))
	late, _ := expiredInvite.Join(other, membership.Timestamp(time.Now().Add(-2*time.Minute)))
	if _, _, err = s.join(ctx, id(other), network, joinRequest{Membership: late, Candidates: []string{}}); !errors.Is(err, errForbidden) {
		t.Fatalf("expired invite: %v", err)
	}
	tampered := reuse
	tampered.Member = "mallory"
	if _, _, err = s.join(ctx, id(other), network, joinRequest{Membership: tampered, Candidates: []string{}}); !errors.Is(err, membership.ErrInvalid) {
		t.Fatalf("tampered chain: %v", err)
	}
	m, err = s.sync(ctx, id(joiner), network, "10.0.0.2:7001", []string{"198.51.100.7:41000", "10.0.0.2:7001"})
	if err != nil || m.Members[0].Address+m.Members[1].Address == "127.0.0.1:7000" {
		t.Fatalf("sync: %v", err)
	}
	// Candidates are stored per member, served unchanged, and replaced on sync.
	served := map[string][]string{}
	for _, member := range m.Members {
		served[member.HostID] = member.Candidates
	}
	if strings.Join(served[id(creator)], ",") != "203.0.113.10:7000" || strings.Join(served[id(joiner)], ",") != "198.51.100.7:41000,10.0.0.2:7001" {
		t.Fatalf("candidates: %v", served)
	}
	if m, err = s.sync(ctx, id(joiner), network, "", []string{}); err != nil {
		t.Fatal(err)
	}
	for _, member := range m.Members {
		if member.HostID == id(joiner) && (member.Candidates == nil || len(member.Candidates) != 0) {
			t.Fatalf("cleared candidates: %#v", member.Candidates)
		}
	}
	if _, err = s.sync(ctx, id(joiner), network, "host:1", []string{}); !errors.Is(err, errInvalid) {
		t.Fatalf("invalid address: %v", err)
	}
	nine := []string{}
	for i := 1; i <= 9; i++ {
		nine = append(nine, fmt.Sprintf("10.0.0.%d:1", i))
	}
	for _, bad := range [][]string{nil, nine, {"10.0.0.1:1", "10.0.0.1:1"}, {""}, {"10.0.0.1:0"}, {"host:1"}, {"[fe80::1%eth0]:1"}} {
		if _, err = s.sync(ctx, id(joiner), network, "", bad); !errors.Is(err, errInvalid) {
			t.Fatalf("invalid candidates %q: %v", bad, err)
		}
	}
	// A member row without stored candidates, such as one injected directly,
	// is served with an empty list.
	if _, err = s.db.ExecContext(ctx, `DELETE FROM member_candidates WHERE host_id = ?`, id(creator)); err != nil {
		t.Fatal(err)
	}
	if m, err = s.sync(ctx, id(joiner), network, "", []string{}); err != nil {
		t.Fatal(err)
	}
	for _, member := range m.Members {
		if member.Candidates == nil || len(member.Candidates) != 0 {
			t.Fatalf("missing candidates not served as []: %#v", member.Candidates)
		}
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
		`{"address":"","candidates":[]}`:           http.StatusForbidden,
		`{"address":null,"candidates":[]}`:         http.StatusBadRequest,
		`{"address":"","candidates":[],"extra":1}`: http.StatusBadRequest,
		`{}`:                                http.StatusBadRequest,
		`{"address":"","candidates":[]} {}`: http.StatusBadRequest,
		`{"address":"127.0.0.1:0","candidates":[]}`:   http.StatusBadRequest,
		`{"address":"127.0.0.1:1","candidates":[]} x`: http.StatusBadRequest,
		`{"address":""}`:                             http.StatusBadRequest,
		`{"address":"","candidates":null}`:           http.StatusBadRequest,
		`{"address":"","candidates":["10.0.0.1:0"]}`: http.StatusBadRequest,
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
