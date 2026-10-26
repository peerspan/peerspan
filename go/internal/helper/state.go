// Package helper implements optional transport resources. It has no network
// authority, host administration, or participant operation storage.
package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var errState = errors.New("invalid private helper state")

type Identity struct {
	Format    uint64 `json:"format"`
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
}

type ownedState struct {
	directory *os.File
	lock      *os.File
	key       ed25519.PrivateKey
	path      string
}

func (s *ownedState) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	if s.directory != nil {
		s.directory.Close()
	}
}

func privateDirectory(path string, create bool) (*os.File, error) {
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode&0777 != 0700 {
		f.Close()
		return nil, errState
	}
	return f, nil
}

func protectedFile(dirfd int, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(dirfd, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Getuid()) || st.Mode&077 != 0 {
		f.Close()
		return nil, errState
	}
	return f, nil
}

func boundedRead(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errState
	}
	return b, nil
}

func readIdentity(dir *os.File) (ed25519.PrivateKey, error) {
	f, err := protectedFile(int(dir.Fd()), "identity.json", unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errState
	}
	b, err := boundedRead(f, 4096)
	if err != nil {
		return nil, err
	}
	var identity Identity
	if strictJSON(b, &identity) != nil || identity.Format != 1 {
		return nil, errState
	}
	seed, err := canonicalBase64(identity.Seed, ed25519.SeedSize)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errState
	}
	key := ed25519.NewKeyFromSeed(seed)
	if identity.PublicKey != base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) {
		return nil, errState
	}
	return key, nil
}

// PublicIdentity is read-only: even a missing directory remains missing.
func PublicIdentity(path string) (string, error) {
	dir, err := privateDirectory(path, false)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	key, err := readIdentity(dir)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

func ownState(path string) (*ownedState, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := privateDirectory(path, true)
	if err != nil {
		return nil, err
	}
	s := &ownedState{directory: dir, path: path}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	s.lock, err = protectedFile(int(dir.Fd()), "helper.lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	info, err := s.lock.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errState
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("helper state already owned")
	}
	s.key, err = readIdentity(dir)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return nil, err
		}
		s.key = ed25519.NewKeyFromSeed(seed)
		identity := Identity{1, base64.StdEncoding.EncodeToString(seed), base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))}
		b, marshalErr := json.Marshal(identity)
		if marshalErr != nil {
			return nil, marshalErr
		}
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		temp := ".identity-" + hex.EncodeToString(nonce[:])
		f, createErr := protectedFile(int(dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
		if createErr != nil {
			return nil, createErr
		}
		defer unix.Unlinkat(int(dir.Fd()), temp, 0)
		_, err = f.Write(append(b, '\n'))
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			// Atomic, no replacement of an unexpected existing identity.
			err = unix.Linkat(int(dir.Fd()), temp, int(dir.Fd()), "identity.json", 0)
		}
		if err == nil {
			err = dir.Sync()
		}
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func canonicalBase64(value string, limit int) ([]byte, error) {
	if len(value) > ((limit+2)/3)*4 {
		return nil, errState
	}
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) > limit || base64.StdEncoding.EncodeToString(b) != value {
		return nil, errState
	}
	return b, nil
}

// strictJSON rejects duplicate names and null at every depth before typed
// decoding, which also rejects missing/incorrectly typed fields at call sites.
func strictJSON(b []byte, target any) error {
	if !utf8.Valid(b) {
		return errState
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errState
		}
		token, err := dec.Token()
		if err != nil || token == nil {
			return errState
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				name, err := dec.Token()
				key, valid := name.(string)
				if err != nil || !valid || seen[key] {
					return errState
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errState
			}
		case json.Delim('['):
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errState
			}
		case json.Delim('}'), json.Delim(']'):
			return errState
		}
		return nil
	}
	if value(0) != nil {
		return errState
	}
	if _, err := dec.Token(); err != io.EOF {
		return errState
	}
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}

type resourceAccounts map[string]string

func loadAccounts(path string) (resourceAccounts, error) {
	if path == "" {
		return nil, nil
	}
	f, err := protectedFile(unix.AT_FDCWD, path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := boundedRead(f, 1<<20)
	if err != nil {
		return nil, err
	}
	var config struct {
		Format   uint64 `json:"format"`
		Accounts []struct {
			ID     string   `json:"id"`
			Tokens []string `json:"tokens"`
		} `json:"accounts"`
	}
	if strictJSON(b, &config) != nil || config.Format != 1 || config.Accounts == nil || len(config.Accounts) > 1024 {
		return nil, errState
	}
	accounts := resourceAccounts{}
	pattern := regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)
	previous := ""
	for _, account := range config.Accounts {
		if !pattern.MatchString(account.ID) || account.ID <= previous || len(account.Tokens) < 1 || len(account.Tokens) > 8 {
			return nil, errState
		}
		previous = account.ID
		var before []byte
		for _, encoded := range account.Tokens {
			token, err := canonicalBase64(encoded, 1024)
			if err != nil || len(token) == 0 || !validToken(token) || before != nil && bytes.Compare(before, token) >= 0 {
				return nil, errState
			}
			if _, exists := accounts[string(token)]; exists {
				return nil, errState
			}
			accounts[string(token)] = account.ID
			before = token
		}
	}
	return accounts, nil
}

func validToken(token []byte) bool {
	return utf8.Valid(token) && !bytes.ContainsAny(token, "\r\n\x00")
}
