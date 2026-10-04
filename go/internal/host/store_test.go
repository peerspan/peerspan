package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "host")
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestRestartPreservesIdentityAndAgentsButDisconnectsSessions(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	identity := s.Identity()
	agent, err := s.RegisterAgent(ctx, RegisterAgent{Name: "bob", Owner: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.AttachSession(ctx, AttachSession{AgentID: agent.ID, Integration: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, s.dir); err == nil {
		t.Fatal("second store acquired live host state")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(ctx, s.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.Identity() != identity {
		t.Fatal("host identity changed")
	}
	if actual, err := restarted.Agent(ctx, agent.ID); err != nil || actual.Name != agent.Name {
		t.Fatalf("agent was lost: %v %v", actual, err)
	}
	actual, err := restarted.Session(ctx, session.ID)
	if err != nil || actual.State != SessionDetached {
		t.Fatalf("stale session advertised as attached: %v %v", actual, err)
	}
	events, err := restarted.Events(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[2].Kind != "session.disconnected" {
		t.Fatalf("missing restart activity: %v", events)
	}
}

func TestMutationAndActivityCommitTogether(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected event failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAgent(ctx, RegisterAgent{Name: "bob", Owner: "bob"}); err == nil {
		t.Fatal("expected activity failure")
	}
	agents, err := s.Agents(ctx)
	if err != nil || len(agents) != 0 {
		t.Fatalf("agent committed without activity: %v %v", agents, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_event`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAgent(ctx, RegisterAgent{Name: "bob", Owner: "bob"}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRegistrationHasOneWinner(t *testing.T) {
	s := openStore(t)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RegisterAgent(context.Background(), RegisterAgent{Name: "bob", Owner: "bob"})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatalf("unexpected registration error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful registrations", winners)
	}
	events, err := s.Events(context.Background(), 0, 100)
	if err != nil || len(events) != 1 {
		t.Fatalf("unexpected activity: %v %v", events, err)
	}
}

func TestPrivateStateAndSocketFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "host")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("accepted public state directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "host.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("followed state symlink")
	}
	if contents, err := os.ReadFile(outside); err != nil || string(contents) != "keep" {
		t.Fatal("overwrote unrelated file")
	}
	s := openStore(t)
	if err := os.WriteFile(s.SocketPath(), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Listen(); err == nil {
		t.Fatal("overwrote non-socket file")
	}
	if contents, err := os.ReadFile(s.SocketPath()); err != nil || string(contents) != "keep" {
		t.Fatal("overwrote socket-path file")
	}
}
