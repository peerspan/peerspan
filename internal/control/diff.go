package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func copyWorkspace(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		return copyFile(path, target)
	})
}

func diffWorkspace(before, after string) (string, []string, error) {
	oldFiles, err := workspaceFiles(before)
	if err != nil {
		return "", nil, err
	}
	newFiles, err := workspaceFiles(after)
	if err != nil {
		return "", nil, err
	}
	seen := map[string]struct{}{}
	for rel := range oldFiles {
		seen[rel] = struct{}{}
	}
	for rel := range newFiles {
		seen[rel] = struct{}{}
	}
	rels := make([]string, 0, len(seen))
	for rel := range seen {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	var patch strings.Builder
	var changed []string
	for _, rel := range rels {
		oldPath := filepath.Join(before, rel)
		newPath := filepath.Join(after, rel)
		same, err := sameFile(oldPath, newPath)
		if err != nil {
			return "", nil, err
		}
		if same {
			continue
		}
		chunk, err := unifiedDiff(oldPath, newPath, filepath.ToSlash(rel))
		if err != nil {
			return "", nil, err
		}
		changed = append(changed, filepath.ToSlash(rel))
		patch.WriteString(chunk)
		if !strings.HasSuffix(chunk, "\n") {
			patch.WriteByte('\n')
		}
	}
	return patch.String(), changed, nil
}

func workspaceFiles(root string) (map[string]struct{}, error) {
	files := map[string]struct{}{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.Type().IsRegular() {
			files[rel] = struct{}{}
		}
		return nil
	})
	return files, err
}

func sameFile(oldPath, newPath string) (bool, error) {
	oldHash, oldErr := hashFile(oldPath)
	newHash, newErr := hashFile(newPath)
	if os.IsNotExist(oldErr) && os.IsNotExist(newErr) {
		return true, nil
	}
	if os.IsNotExist(oldErr) || os.IsNotExist(newErr) {
		return false, nil
	}
	if oldErr != nil {
		return false, oldErr
	}
	if newErr != nil {
		return false, newErr
	}
	return oldHash == newHash, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func unifiedDiff(oldPath, newPath, rel string) (string, error) {
	oldLabel := "a/" + rel
	newLabel := "b/" + rel
	left := oldPath
	right := newPath
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		left = "/dev/null"
	}
	if _, err := os.Stat(newPath); os.IsNotExist(err) {
		right = "/dev/null"
	}
	cmd := exec.Command("diff", "-u", "--label", oldLabel, "--label", newLabel, left, right)
	out, err := cmd.Output()
	if err == nil {
		return "", nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return string(out), nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" && exitErr != nil {
		msg = strings.TrimSpace(string(exitErr.Stderr))
	}
	if msg == "" {
		return "", fmt.Errorf("diff %s: %w", rel, err)
	}
	return "", fmt.Errorf("diff %s: %w: %s", rel, err, msg)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
