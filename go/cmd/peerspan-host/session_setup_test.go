package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSessionSetupRelativeExpiryValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"both", []string{"setup", "--directory", "/tmp/profile", "--harness", "test", "--agent", "agent_x", "--expires-at", "2099-01-01T00:00:00Z", "--expires-in", "2h"}, "mutually exclusive"},
		{"fractional", []string{"setup", "--directory", "/tmp/profile", "--harness", "test", "--agent", "agent_x", "--expires-in", "1h30m"}, "whole-minute or whole-hour"},
		{"too short", []string{"setup", "--directory", "/tmp/profile", "--harness", "test", "--agent", "agent_x", "--expires-in", "0m"}, "from 1m to 720h"},
		{"too long", []string{"setup", "--directory", "/tmp/profile", "--harness", "test", "--agent", "agent_x", "--expires-in", "721h"}, "from 1m to 720h"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--state", t.TempDir(), "session"}, test.args...)
			err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestRelativeExpiryDuration(t *testing.T) {
	for input, want := range map[string]string{"1m": "1m0s", "24h": "24h0m0s", "720h": "720h0m0s"} {
		got, err := relativeExpiryDuration(input)
		if err != nil || got.String() != want {
			t.Fatalf("relativeExpiryDuration(%q) = %v, %v; want %s", input, got, err, want)
		}
	}
	for _, input := range []string{"", "0m", "30s", "1h30m", "721h", "999999999999999999999h", "1é", "1💥"} {
		if _, err := relativeExpiryDuration(input); err == nil {
			t.Fatalf("relativeExpiryDuration(%q) succeeded", input)
		}
	}
}
