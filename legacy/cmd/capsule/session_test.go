package main

import (
	"flag"
	"testing"
)

func TestParseSessionArgsIDFirst(t *testing.T) {
	fs := flag.NewFlagSet("session accept", flag.ContinueOnError)
	capsuleID := fs.String("capsule", "", "")
	var allow multiFlag
	fs.Var(&allow, "allow", "")
	id, err := parseSessionArgs(fs, []string{"ses-one", "--capsule", "cap-two", "--allow", "notes/diag.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "ses-one" || *capsuleID != "cap-two" || len(allow) != 1 || allow[0] != "notes/diag.txt" {
		t.Fatalf("id=%q capsule=%q allow=%v", id, *capsuleID, allow)
	}
}

func TestParseSessionArgsIDLast(t *testing.T) {
	fs := flag.NewFlagSet("session accept", flag.ContinueOnError)
	capsuleID := fs.String("capsule", "", "")
	id, err := parseSessionArgs(fs, []string{"--capsule", "cap-two", "ses-one"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "ses-one" || *capsuleID != "cap-two" {
		t.Fatalf("id=%q capsule=%q", id, *capsuleID)
	}
}

func TestParseSessionArgsMissingID(t *testing.T) {
	fs := flag.NewFlagSet("session accept", flag.ContinueOnError)
	fs.String("capsule", "", "")
	if _, err := parseSessionArgs(fs, []string{"--capsule", "cap-two"}); err == nil {
		t.Fatal("expected a missing session id to fail")
	}
}
