package store

import (
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
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
