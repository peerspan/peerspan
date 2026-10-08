package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Cerebral-Systems/capsule/go/internal/coord"
	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	cmd := newCommand(out, errOut)
	cmd.SetArgs(args)
	return cmd.ExecuteContext(ctx)
}

func newCommand(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use: "capsule-coord", Short: "Run the Capsule coordination service",
		Long:         "Coordination stores signed membership chains and serves network maps. It carries no collaboration traffic, and hosts verify every chain it serves.",
		SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.CompletionOptions.DisableDefaultCmd = true
	var state, listen string
	limits := coord.DefaultLimits
	root.PersistentFlags().StringVar(&state, "state", "", "private state directory")
	resolveState := func(cmd *cobra.Command, args []string) error {
		if state == "" {
			var err error
			state, err = coord.DefaultStateDir()
			return err
		}
		return nil
	}

	info := &cobra.Command{
		Use: "info", Short: "Show the coordinator's public identity", Args: cobra.NoArgs,
		PreRunE: resolveState,
		RunE: func(cmd *cobra.Command, args []string) error {
			identity, err := coord.ReadIdentity(cmd.Context(), state)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(identity)
		},
	}
	serve := &cobra.Command{
		Use: "run", Short: "Run the coordinator in the foreground", Args: cobra.NoArgs,
		PreRunE: resolveState,
		RunE: func(cmd *cobra.Command, args []string) error {
			if listen == "" {
				return fmt.Errorf("run requires --listen HOST:PORT")
			}
			if limits.MaxMembers < 0 || limits.MaxNetworksPerIP < 0 || limits.RelayBytesPerMonth < 0 {
				return fmt.Errorf("limits must be 0 (disabled) or positive")
			}
			server, err := coord.Open(cmd.Context(), state)
			if err != nil {
				return err
			}
			defer server.Close()
			server.Limits = limits
			listener, err := server.Listen(listen)
			if err != nil {
				return err
			}
			defer listener.Close()
			fmt.Fprintf(cmd.ErrOrStderr(), "coordinator %s listening on %s\n", server.Identity().ID, listener.Addr())
			return server.Serve(cmd.Context(), listener)
		},
	}
	serve.Flags().StringVar(&listen, "listen", "", "bind address, HOST:PORT")
	serve.Flags().Int64Var(&limits.MaxMembers, "max-members", limits.MaxMembers, "current member hosts per network; 0 disables")
	serve.Flags().Int64Var(&limits.MaxNetworksPerIP, "max-networks-per-ip", limits.MaxNetworksPerIP, "network registrations per source address (IPv6 by /64) in any 24 hours; 0 disables")
	serve.Flags().Int64Var(&limits.RelayBytesPerMonth, "relay-bytes-per-month", limits.RelayBytesPerMonth, "relayed datagram bytes per network per UTC calendar month; 0 disables")
	root.AddCommand(info, serve)
	return root
}
