package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/peerspan/peerspan/go/internal/helper"
	"github.com/spf13/cobra"
)

func defaultState() string {
	if directory := os.Getenv("XDG_STATE_HOME"); directory != "" {
		return filepath.Join(directory, "peerspan", "helper")
	}
	directory, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, ".local", "state", "peerspan", "helper")
}

func main() {
	var options helper.ServeOptions
	command := &cobra.Command{Use: "peerspan-helper", Short: "Optional encrypted transport resources", SilenceUsage: true, SilenceErrors: true}
	command.PersistentFlags().StringVar(&options.State, "state", defaultState(), "Private helper state directory")
	serve := &cobra.Command{Use: "serve", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if options.State == "" {
			return errors.New("missing state directory")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return helper.Serve(ctx, options, command.OutOrStdout())
	}}
	serve.Flags().StringVar(&options.Listen, "listen", "", "Explicit TCP bind address HOST:PORT")
	serve.Flags().StringVar(&options.TokensFile, "tokens-file", "", "Protected resource credential configuration")
	_ = serve.MarkFlagRequired("listen")
	info := &cobra.Command{Use: "info", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		err := helper.Info(options.State, command.OutOrStdout())
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("not_found")
		}
		return err
	}}
	command.AddCommand(serve, info)
	if err := command.Execute(); err != nil {
		// Only bounded operator diagnostics; never echo resource credentials,
		// packet contents, ciphertext, or private key material.
		if err.Error() == "not_found" {
			fmt.Fprintln(os.Stderr, "not_found")
		} else {
			fmt.Fprintln(os.Stderr, "helper failed; check flags, private state and resource configuration")
		}
		os.Exit(1)
	}
}
