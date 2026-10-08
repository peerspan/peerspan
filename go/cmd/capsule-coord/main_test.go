package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpWithoutState(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	for _, args := range [][]string{nil, {"--help"}, {"help", "run"}, {"run", "--help"}, {"info", "--help"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("%v: missing help", args)
		}
	}
}

func TestRejectInvalidArgumentsBeforeOpeningState(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"info", "extra"}, {"run"}, {"run", "--listen"}, {"run", "extra", "--listen", "127.0.0.1:0"}} {
		state := filepath.Join(t.TempDir(), "state")
		err := run(context.Background(), append([]string{"--state", state}, args...), io.Discard, io.Discard)
		if err == nil {
			t.Fatalf("%v accepted", args)
		}
		if _, statErr := os.Stat(state); !os.IsNotExist(statErr) {
			t.Fatalf("%v touched state: %v", args, statErr)
		}
	}
}
