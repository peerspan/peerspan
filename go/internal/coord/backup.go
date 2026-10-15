package coord

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Backup and restore of the coordinator database. A backup includes the
// private key, so every file written here is mode 0600.

// BackupResult is printed by peerspan-coord backup.
type BackupResult struct {
	File        string `json:"file"`
	Bytes       int64  `json:"bytes"`
	ID          string `json:"id"`
	UserVersion int    `json:"user_version"`
}

// RestoreResult is printed by peerspan-coord restore.
type RestoreResult struct {
	ID          string  `json:"id"`
	UserVersion int     `json:"user_version"`
	Replaced    *string `json:"replaced"`
}

// ErrRunning is a restore refused because the state lock is held.
var ErrRunning = errors.New("coordinator is running")

// tempName is an unused name for a temporary file beside path.
func tempName(path string) (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix[:])), nil
}

func removeDB(path string) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(path + suffix)
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// checkDB verifies that a database file is a coordinator database this
// build opens: integrity_check is ok, its user_version is supported, and it
// has a valid identity row (and valid successors). The identity is the
// latest one.
func checkDB(ctx context.Context, path string) (Identity, int, error) {
	db, err := openDB(path, false)
	if err != nil {
		return Identity{}, 0, err
	}
	defer db.Close()
	var result string
	if err = db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return Identity{}, 0, fmt.Errorf("not a usable SQLite database: %w", err)
	}
	if result != "ok" {
		return Identity{}, 0, fmt.Errorf("database integrity check failed: %s", result)
	}
	var version int
	if err = db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return Identity{}, 0, err
	}
	if version < 1 || version > schemaVersion {
		return Identity{}, 0, fmt.Errorf("unsupported coordinator database version: %d", version)
	}
	identities, err := readIdentities(ctx, db, version)
	if err != nil {
		return Identity{}, 0, fmt.Errorf("not a coordinator database: %w", err)
	}
	return identities[len(identities)-1].identity, version, nil
}

// Backup writes a consistent copy of the state's database to file with
// VACUUM INTO, without taking the state lock, so it works while the
// coordinator runs. An existing file is refused.
func Backup(ctx context.Context, dir, file string) (_ *BackupResult, err error) {
	dir, err = privateDir(dir, false)
	if err != nil {
		return nil, err
	}
	source := filepath.Join(dir, "coord.db")
	f, err := privateFile(source, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("coordinator state is not initialized: %w", err)
	}
	f.Close()
	if file, err = filepath.Abs(file); err != nil {
		return nil, err
	}
	if found, err := exists(file); err != nil || found {
		return nil, errors.Join(err, fmt.Errorf("backup file already exists: %s", file))
	}
	temp, err := tempName(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			removeDB(temp)
		}
	}()
	// The empty file fixes the mode at 0600 before VACUUM INTO fills it.
	out, err := privateFile(temp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return nil, err
	}
	out.Close()
	db, err := openDB(source, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// The running service may hold a write lock briefly; wait instead of failing.
	if _, err = db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return nil, err
	}
	if _, err = db.ExecContext(ctx, `VACUUM INTO ?`, temp); err != nil {
		return nil, err
	}
	identity, version, err := checkDB(ctx, temp)
	if err != nil {
		return nil, err
	}
	if out, err = privateFile(temp, unix.O_RDWR); err != nil {
		return nil, err
	}
	info, err := out.Stat()
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if found, err := exists(file); err != nil || found {
		return nil, errors.Join(err, fmt.Errorf("backup file already exists: %s", file))
	}
	if err = os.Rename(temp, file); err != nil {
		return nil, err
	}
	if err = syncDir(filepath.Dir(file)); err != nil {
		return nil, err
	}
	return &BackupResult{File: file, Bytes: info.Size(), ID: identity.ID, UserVersion: version}, nil
}

// Restore installs a backup file as the state's database. It holds the state
// lock throughout, and with replace keeps any previous database beside it as
// coord.db.replaced-TIMESTAMP.
func Restore(ctx context.Context, dir, file string, replace bool) (_ *RestoreResult, err error) {
	if dir, err = filepath.Abs(dir); err != nil {
		return nil, err
	}
	// A refused restore leaves no state directory it created.
	created, err := exists(dir)
	created = !created && err == nil
	if dir, err = privateDir(dir, true); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "coord.lock")
	lock, err := privateFile(lockPath, unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	defer func() {
		lock.Close()
		if err != nil && created {
			_ = os.Remove(lockPath)
			_ = os.Remove(dir)
		}
	}()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	path := filepath.Join(dir, "coord.db")
	had, err := exists(path)
	if err != nil {
		return nil, err
	}
	if had && !replace {
		return nil, fmt.Errorf("the state already has a database; use --replace to keep it as coord.db.replaced-TIMESTAMP and restore over it")
	}
	// The backup is copied, then checked, so what is checked is what is
	// installed; the copy is removed if it fails.
	temp, err := tempName(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			removeDB(temp)
		}
	}()
	if err = copyPrivate(file, temp); err != nil {
		return nil, err
	}
	identity, version, err := checkDB(ctx, temp)
	if err != nil {
		return nil, err
	}
	// checkDB may leave journal files beside the copy.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_ = os.Remove(temp + suffix)
	}
	result := &RestoreResult{ID: identity.ID, UserVersion: version}
	if had {
		kept := filepath.Join(dir, "coord.db.replaced-"+time.Now().UTC().Format("20060102T150405Z"))
		if found, err := exists(kept); err != nil || found {
			return nil, errors.Join(err, fmt.Errorf("%s already exists; retry in a second", kept))
		}
		if err = os.Rename(path, kept); err != nil {
			return nil, err
		}
		// An uncheckpointed write-ahead log belongs to the previous
		// database, so it moves with it.
		if found, _ := exists(path + "-wal"); found {
			if err = os.Rename(path+"-wal", kept+"-wal"); err != nil {
				return nil, err
			}
		}
		result.Replaced = &kept
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err = os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if err = os.Rename(temp, path); err != nil {
		return nil, err
	}
	return result, syncDir(dir)
}

// copyPrivate copies src to a new mode 0600 file dst and syncs it.
func copyPrivate(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if info, err := in.Stat(); err != nil || !info.Mode().IsRegular() {
		return errors.Join(err, fmt.Errorf("backup must be a regular file: %s", src))
	}
	out, err := privateFile(dst, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
