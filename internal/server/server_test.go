package server_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Cerebral-Systems/capsule/internal/client"
	"github.com/Cerebral-Systems/capsule/internal/control"
	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/server"
	"github.com/Cerebral-Systems/capsule/internal/session"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestTwoClientsShareOneServer(t *testing.T) {
	svc := control.Service{
		Store:   store.Store{Dir: t.TempDir()},
		Runtime: local.Runtime{},
	}
	ts := httptest.NewServer(server.Handler(svc))
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		capsules, err := svc.List()
		if err != nil {
			return
		}
		for _, c := range capsules {
			_, _ = svc.Destroy(c.ID)
		}
	})

	a := client.Client{BaseURL: ts.URL}
	b := client.Client{BaseURL: ts.URL}
	ctx := context.Background()

	opened, err := a.Create(ctx, control.CreateRequest{
		Task:         "customer issue",
		Setup:        "printf fail > failure.txt",
		Capabilities: []string{"share"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := b.Create(ctx, control.CreateRequest{Task: "vendor debug"})
	if err != nil {
		t.Fatal(err)
	}

	listed, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("list = %d", len(listed))
	}

	sess, err := a.CreateSession(ctx, control.CreateSessionRequest{
		CapsuleID: opened.ID,
		Task:      "staging failure",
		Allow:     []string{"failure.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.AcceptSession(ctx, sess.ID, joined.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.MessageSession(ctx, sess.ID, opened.ID, "log attached"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ShareSession(ctx, sess.ID, opened.ID, "failure.txt"); err != nil {
		t.Fatal(err)
	}
	exported, err := b.ExportSession(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Status != session.StatusActive || len(exported.Transcript) != 1 || len(exported.Artifacts) != 1 {
		t.Fatalf("export = %+v", exported)
	}
	if len(exported.Participants) != 2 || exported.Participants[0].Role != "opened" {
		t.Fatalf("participants = %+v", exported.Participants)
	}
}
