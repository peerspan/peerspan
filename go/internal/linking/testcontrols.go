package linking

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RuntimeNow keeps conformance clock injection separate from real-time I/O
// deadlines. Only an explicitly enabled process environment can select it.
func RuntimeNow(normal func() time.Time) (time.Time, error) {
	if os.Getenv("PEERSPAN_LINK_TEST_MODE") != "1" || os.Getenv("PEERSPAN_LINK_TEST_CLOCK_FILE") == "" {
		return normal().UTC(), nil
	}
	b, err := os.ReadFile(os.Getenv("PEERSPAN_LINK_TEST_CLOCK_FILE"))
	if err != nil || len(b) > 21 {
		return time.Time{}, fmt.Errorf("invalid linking test clock")
	}
	t, err := stamp(strings.TrimSuffix(string(b), "\n"))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid linking test clock")
	}
	return t, nil
}

// RuntimeBarrier is an opt-in crash/restart conformance rendezvous. Names are
// implementation constants and its only output is a public request ID.
func RuntimeBarrier(ctx context.Context, name, requestID string) error {
	dir := os.Getenv("PEERSPAN_LINK_TEST_BARRIER_DIR")
	if os.Getenv("PEERSPAN_LINK_TEST_MODE") != "1" || dir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, name+".arm")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".entered"), []byte(requestID), 0o600); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(dir, name+".continue")); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
