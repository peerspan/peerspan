package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

func TestSaveLoadList(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	now := time.Date(2026, 9, 29, 20, 0, 0, 0, time.UTC)
	first := capsule.Capsule{
		ID:        "cap-one",
		Task:      "first",
		Status:    capsule.StatusCreated,
		CreatedAt: now,
		UpdatedAt: now,
	}
	second := capsule.Capsule{
		ID:        "cap-two",
		Task:      "second",
		Status:    capsule.StatusCreated,
		CreatedAt: now.Add(time.Second),
		UpdatedAt: now.Add(time.Second),
	}
	if err := s.Save(second); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(first); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load("cap-one")
	if err != nil {
		t.Fatal(err)
	}
	if got.Task != "first" {
		t.Fatalf("task = %q", got.Task)
	}

	all, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != "cap-one" || all[1].ID != "cap-two" {
		t.Fatalf("list = %+v", all)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "cap-one", "record.json")); !os.IsNotExist(err) {
		t.Fatal("expected capsule records to live in the database")
	}
}

func TestSessionRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	sess := session.Session{ID: "ses-one", Task: "issue", Status: session.StatusPending, CreatedAt: now}
	if err := s.SaveSession(sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSession("ses-one")
	if err != nil {
		t.Fatal(err)
	}
	if got.Task != "issue" {
		t.Fatalf("task = %q", got.Task)
	}
	all, err := s.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != "ses-one" {
		t.Fatalf("sessions = %+v", all)
	}
	if _, err := os.Stat(filepath.Join(s.SessionDir("ses-one"), "session.json")); !os.IsNotExist(err) {
		t.Fatal("expected session records to live in the database")
	}
}

func TestLoadMissing(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.Load("missing"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRejectsPathID(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	err := s.Save(capsule.Capsule{ID: "../escape"})
	if err == nil {
		t.Fatal("expected an error")
	}
}
