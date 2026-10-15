package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func DefaultStateDir() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
		return filepath.Join(dir, "peerspan", "host"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "peerspan", "host"), nil
}

// Listen is called after Open has acquired the exclusive state lock. A stale
// socket can then be removed safely; unrelated files are never overwritten.
func (s *Store) Listen() (*net.UnixListener, error) {
	return listenSocket(s.SocketPath())
}

func (s *Store) ListenAdapter() (*net.UnixListener, error) {
	return listenSocket(filepath.Join(s.dir, "adapter.sock"))
}

func listenSocket(path string) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path contains a non-socket file: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// Serve stops accepting requests on cancellation, drains outstanding local
// requests, and returns before the caller closes the store.
func Serve(ctx context.Context, listener net.Listener, handler http.Handler) error {
	return serve(ctx, listener, handler, 15*time.Second)
}

// ServeLocal is Serve for the owner's and adapters' local sockets. A local
// request may wait on several coordinator calls and syncs, so it may write
// its response for as long as the CLI waits (one minute), rather than being
// cut off with EOF.
func ServeLocal(ctx context.Context, listener net.Listener, handler http.Handler) error {
	return serve(ctx, listener, handler, 65*time.Second)
}

func serve(ctx context.Context, listener net.Listener, handler http.Handler, write time.Duration) error {
	server := &http.Server{Handler: handler, ConnContext: peerConnContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: write, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		serveErr := <-done
		if !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
		return err
	}
}
