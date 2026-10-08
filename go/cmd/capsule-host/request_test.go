package main

import (
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// Exercise the real parser while inspecting requests without a running daemon.
func request(args []string, errOut io.Writer) (method, path string, body any, err error) {
	root := newCommand(io.Discard, errOut)
	var replace func(*cobra.Command)
	replace = func(cmd *cobra.Command) {
		if cmd.RunE != nil && cmd != root {
			cmd.RunE = func(cmd *cobra.Command, positional []string) error {
				parts := strings.Fields(strings.TrimPrefix(cmd.CommandPath(), "capsule-host "))
				var buildErr error
				method, path, body, buildErr = buildRequest(append(parts, positional...), cmd.Flags())
				return buildErr
			}
		}
		for _, child := range cmd.Commands() {
			replace(child)
		}
	}
	replace(root)
	root.SetArgs(args)
	err = root.Execute()
	return
}
