package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
		var exit *exitError
		if !errors.As(err, &exit) || !exit.logged {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		if errors.As(err, &exit) {
			os.Exit(exit.code)
		}
		os.Exit(1)
	}
}

// exitError sets the exit status; logged errors were already written to
// stderr as a JSON line.
type exitError struct {
	code   int
	logged bool
	err    error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

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
	var state, listen, opsListen string
	var replace bool
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
			if opsListen != "" {
				if err := coord.CheckOpsAddress(opsListen); err != nil {
					return &exitError{code: 2, err: err}
				}
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
			log := coord.NewLogger(cmd.ErrOrStderr())
			server.Log = log
			listener, err := server.Listen(listen)
			if err != nil {
				return err
			}
			defer listener.Close()
			opsAddress := slog.Any("ops_listen", nil)
			var ops net.Listener
			if opsListen != "" {
				if ops, err = net.Listen("tcp", opsListen); err != nil {
					return err
				}
				defer ops.Close()
				opsAddress = slog.String("ops_listen", ops.Addr().String())
			}
			log.LogAttrs(cmd.Context(), slog.LevelInfo, "start", slog.String("id", server.Identity().ID), slog.String("listen", listener.Addr().String()), opsAddress)
			// The ops listener stops with the coordinator; its failure is
			// logged but does not stop coordination.
			opsCtx, stopOps := context.WithCancel(cmd.Context())
			opsDone := make(chan struct{})
			go func() {
				defer close(opsDone)
				if ops == nil {
					return
				}
				if err := server.ServeOps(opsCtx, ops); err != nil {
					coord.LogError(log, "the ops listener stopped serving: "+err.Error(), "", "")
				}
			}()
			err = server.Serve(cmd.Context(), listener)
			stopOps()
			<-opsDone
			if err != nil {
				coord.LogError(log, "the coordinator stopped serving: "+err.Error(), "", "")
			}
			log.LogAttrs(context.Background(), slog.LevelInfo, "stop")
			if err != nil {
				return &exitError{code: 1, logged: true, err: err}
			}
			return nil
		},
	}
	serve.Flags().StringVar(&listen, "listen", "", "bind address, HOST:PORT")
	serve.Flags().Int64Var(&limits.MaxMembers, "max-members", limits.MaxMembers, "current member hosts per network; 0 disables")
	serve.Flags().Int64Var(&limits.MaxNetworksPerIP, "max-networks-per-ip", limits.MaxNetworksPerIP, "network registrations per source address (IPv6 by /64) in any 24 hours; 0 disables")
	serve.Flags().Int64Var(&limits.RelayBytesPerMonth, "relay-bytes-per-month", limits.RelayBytesPerMonth, "relayed datagram bytes per network per UTC calendar month; 0 disables")
	serve.Flags().StringVar(&opsListen, "ops-listen", "", "loopback address for /healthz and /metrics, HOST:PORT; off by default")
	backup := &cobra.Command{
		Use: "backup FILE", Short: "Write a consistent copy of the database, including the private key", Args: cobra.ExactArgs(1),
		Long:    "Backup writes a consistent copy of the coordinator database, which includes its private key, to a new mode 0600 FILE. It works while the coordinator runs.",
		PreRunE: resolveState,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := coord.Backup(cmd.Context(), state, args[0])
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	restore := &cobra.Command{
		Use: "restore FILE", Short: "Install a backup as the coordinator database", Args: cobra.ExactArgs(1),
		Long:    "Restore checks a backup file and installs it as the state's database while the coordinator is stopped. With --replace, the previous database is kept as coord.db.replaced-TIMESTAMP.",
		PreRunE: resolveState,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := coord.Restore(cmd.Context(), state, args[0], replace)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	restore.Flags().BoolVar(&replace, "replace", false, "replace an existing database, keeping it beside the restored one")
	root.AddCommand(info, serve, backup, restore)
	return root
}
