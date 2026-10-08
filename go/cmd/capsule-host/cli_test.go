package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestHelpDoesNotOpenState(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	root := newCommand(io.Discard, io.Discard)
	paths := [][]string{nil, {"help"}, {"--help"}, {"agent"}, {"network", "group"}}
	var collect func(*cobra.Command, []string)
	collect = func(cmd *cobra.Command, path []string) {
		for _, child := range cmd.Commands() {
			next := append(append([]string{}, path...), child.Name())
			paths = append(paths, append(append([]string{}, next...), "--help"))
			collect(child, next)
		}
	}
	collect(root, nil)
	for _, args := range paths {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if err := run(context.Background(), args, &out, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Usage:") {
				t.Fatalf("missing help: %s", out.String())
			}
		})
	}
}

func TestFlagAndArgumentParsing(t *testing.T) {
	for _, tc := range []struct {
		args       []string
		path       string
		positional []string
		state      string
		flag       string
		values     []string
		dash       int
	}{
		{[]string{"agent", "register", "--state", "private state", "--capability", "a,b", "--capability=c"}, "capsule-host agent register", nil, "private state", "capability", []string{"a,b", "c"}, -1},
		{[]string{"message", "inspect", "id with spaces", "--peer=host_x", "--state=/private"}, "capsule-host message inspect", []string{"id with spaces"}, "/private", "", nil, -1},
		{[]string{"network", "group", "set", "--person-key=/keys/my key", "--person", "a,b", "--person", "c"}, "capsule-host network group set", nil, "", "person", []string{"a,b", "c"}, -1},
		{[]string{"serve", "--state=/private"}, "capsule-host run", nil, "/private", "", nil, -1},
		{[]string{"session", "start", "--directory", "setup dir", "--", "--help", "--state", "harness state"}, "capsule-host session start", []string{"--help", "--state", "harness state"}, "", "", nil, 0},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			root := newCommand(io.Discard, io.Discard)
			var replace func(*cobra.Command)
			replace = func(cmd *cobra.Command) {
				if cmd.RunE != nil {
					cmd.RunE = func(cmd *cobra.Command, args []string) error {
						state, _ := cmd.Flags().GetString("state")
						if cmd.CommandPath() != tc.path || strings.Join(args, "|") != strings.Join(tc.positional, "|") || state != tc.state || cmd.Flags().ArgsLenAtDash() != tc.dash {
							t.Fatalf("parsed %s %v state=%q dash=%d", cmd.CommandPath(), args, state, cmd.Flags().ArgsLenAtDash())
						}
						if tc.flag != "" {
							values, err := cmd.Flags().GetStringArray(tc.flag)
							if err != nil || !reflect.DeepEqual(values, tc.values) {
								t.Fatalf("values %v: %v", values, err)
							}
						}
						if strings.HasPrefix(tc.path, "capsule-host network") && personKey(cmd.Flags()) != "/keys/my key" {
							t.Fatal("person key was not parsed")
						}
						return nil
					}
				}
				for _, child := range cmd.Commands() {
					replace(child)
				}
			}
			replace(root)
			root.SetArgs(tc.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParserAndDaemonValidationBeforeStateCreation(t *testing.T) {
	for _, args := range [][]string{
		{"unknown"}, {"agent", "unknown"}, {"network", "group", "unknown"},
		{"info", "extra"}, {"agent", "inspect"}, {"agent", "register", "--name"},
		{"task", "inspect", "id", "--after", "1"}, {"activity", "--limit", "invalid"},
		{"network", "invite", "--person-key"},
		{"run", "--advertise", "127.0.0.1:1234"}, {"run", "--coordination-interval", "0"},
		{"run", "--artifact-quota", "0"}, {"session", "start", "--directory", "setup", "harness-arg"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			err := run(context.Background(), append([]string{"--state", state}, args...), io.Discard, io.Discard)
			if err == nil {
				t.Fatal("invalid command accepted")
			}
			if _, statErr := os.Stat(state); !os.IsNotExist(statErr) {
				t.Fatalf("state touched: %v", statErr)
			}
		})
	}
}
