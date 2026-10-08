package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func TestHelpAndInvalidArguments(t *testing.T) {
	for _, sub := range []string{"", "sign-link", "link-hash", "submit-task"} {
		cmd := newCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		args := []string{"--help"}
		if sub != "" {
			args = append([]string{sub}, args...)
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("%v missing help", args)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"link-hash", "extra"}, {"sign-link", "extra"}, {"submit-task", "--request"}, {"sign-link", "--index", "invalid"}} {
		cmd := newCommand()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}

func TestSignLinkKeepsRepeatedPrincipalsVerbatim(t *testing.T) {
	cmd := newCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"sign-link", "--seed-hex", strings.Repeat("00", 32), "--principal", "a,b", "--principal=c"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var link membership.Link
	if err := json.Unmarshal(out.Bytes(), &link); err != nil {
		t.Fatal(err)
	}
	if strings.Join(link.Principals, "|") != "a,b|c" {
		t.Fatalf("principals changed: %v", link.Principals)
	}
}
