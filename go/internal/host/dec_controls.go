package host

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"golang.org/x/sys/unix"
)

type decControlError struct {
	cause error
	stage string
}

func (e *decControlError) Error() string         { return "internal" }
func (e *decControlError) Unwrap() error         { return e.cause }
func (e *decControlError) decErrorStage() string { return e.stage }
func decInvalidControl(stage string) error       { return &decControlError{decFailure("internal"), stage} }

func decControlFile(path string, max int, private bool) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, e := file.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || private && info.Mode().Perm() != 0600 {
		return nil, errors.New("invalid control file")
	}
	raw, e := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if e != nil || len(raw) > max {
		return nil, errors.New("invalid control size")
	}
	return raw, nil
}

func decNow() (time.Time, error) {
	if os.Getenv("PEERSPAN_DEC_TEST_MODE") == "1" {
		path := os.Getenv("PEERSPAN_DEC_TEST_CLOCK_FILE")
		if path != "" {
			raw, e := decControlFile(path, 21, false)
			if e != nil {
				return time.Time{}, decInvalidControl("clock")
			}
			at, e := dec.ParseTime(strings.TrimSuffix(string(raw), "\n"))
			if e != nil {
				return time.Time{}, decInvalidControl("clock")
			}
			return at, nil
		}
	}
	return time.Now().UTC().Truncate(time.Second), nil
}

// DecentralizedDecisionTime is local-only for CLI preflight and typed writing.
// Legacy LINK controls and remote/helper time cannot affect this clock.
func DecentralizedDecisionTime() (time.Time, error) { return decNow() }

var decBarrierNames = map[string]bool{
	"dec.intent.after_commit": true, "dec.approval.after_commit": true,
	"dec.frame.after_commit": true, "dec.signature.after_commit": true, "dec.request.after_commit": true,
	"dec.owner.after_commit": true, "dec.selection.after_commit": true,
	"dec.administrator.after_commit": true, "dec.owner_finalization.after_commit": true,
	"dec.requester_commit.after_commit": true, "dec.apply.before_transaction": true,
	"dec.apply.after_commit": true, "dec.migration_proposal.after_commit": true,
	"dec.migration_fence.after_commit": true, "dec.migration_commit.after_commit": true,
}

// decBarrier must be called outside DB transactions and global writer locks.
// It observes a real durable boundary; it never changes operation identity or
// supplies authority. Historical completed returns do not call this function.
func decBarrier(ctx context.Context, name, operation string) error {
	if os.Getenv("PEERSPAN_DEC_TEST_MODE") != "1" {
		return nil
	}
	dir := os.Getenv("PEERSPAN_DEC_TEST_BARRIER_DIR")
	if dir == "" {
		return nil
	}
	if !decBarrierNames[name] || !(dec.ValidID(operation, "create_") || dec.ValidID(operation, "act_") || dec.ValidID(operation, "link_") || dec.ValidID(operation, "ds_")) {
		return decInvalidControl("request")
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return decInvalidControl("request")
	}
	arm, e := decControlFile(filepath.Join(dir, name+".arm"), 128, true)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return decInvalidControl("request")
	}
	target := strings.TrimSuffix(string(arm), "\n")
	if target != "-" && !(dec.ValidID(target, "create_") || dec.ValidID(target, "act_") || dec.ValidID(target, "link_") || dec.ValidID(target, "ds_")) {
		return decInvalidControl("request")
	}
	if target != "-" && target != operation {
		return nil
	}
	fd, e := unix.Open(filepath.Join(dir, name+".entered"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return decInvalidControl("request")
	}
	entered := os.NewFile(uintptr(fd), name)
	stat, e := entered.Stat()
	if e != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 {
		entered.Close()
		return decInvalidControl("request")
	}
	_, e = entered.WriteString(operation)
	closeErr := entered.Close()
	if e != nil || closeErr != nil {
		return decInvalidControl("request")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, e = decControlFile(filepath.Join(dir, name+".continue"), 128, true)
		if e == nil {
			return nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return decInvalidControl("request")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type decCommittedFacts struct {
	operation string
	names     []string
}

func (f *decCommittedFacts) add(name string) { f.names = append(f.names, name) }
func (f *decCommittedFacts) wait(ctx context.Context) error {
	for _, name := range f.names {
		if e := decBarrier(ctx, name, f.operation); e != nil {
			return e
		}
	}
	return nil
}
