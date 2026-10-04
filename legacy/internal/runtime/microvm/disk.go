package microvm

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

func writeWorkspaceImage(src, image string) error {
	if err := createExt4(image, 512<<20); err != nil {
		return err
	}
	return withMount(image, false, func(mnt string) error {
		return copyTree(src, mnt)
	})
}

func writeSecretsImage(dir string, secrets []runtime.Secret) (string, error) {
	if len(secrets) == 0 {
		return "", nil
	}
	image := filepath.Join(dir, "secrets.img")
	if err := createExt4(image, 8<<20); err != nil {
		return "", err
	}
	if err := os.Chmod(image, 0o600); err != nil {
		return "", err
	}
	err := withMount(image, false, func(mnt string) error {
		for _, secret := range secrets {
			in, err := os.Open(secret.HostPath)
			if err != nil {
				return err
			}
			out, err := os.OpenFile(filepath.Join(mnt, secret.Name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o400)
			if err != nil {
				in.Close()
				return err
			}
			_, copyErr := io.Copy(out, in)
			closeErr := out.Close()
			in.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return image, nil
}

func publishWorkspace(image, dst string) error {
	return withMount(image, true, func(mnt string) error {
		entries, err := os.ReadDir(dst)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := os.RemoveAll(filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return copyTree(mnt, dst)
	})
}

func createExt4(image string, size int64) error {
	if err := os.RemoveAll(image); err != nil {
		return err
	}
	f, err := os.OpenFile(image, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	out, err := exec.Command("mkfs.ext4", "-F", "-q", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs.ext4: %w: %s", err, out)
	}
	return nil
}

func withMount(image string, readOnly bool, fn func(string) error) error {
	mnt, err := os.MkdirTemp("", "capsule-mnt-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mnt)
	opts := "loop"
	if readOnly {
		opts = "loop,ro"
	}
	mount := exec.Command("mount", "-o", opts, image, mnt)
	if out, err := mount.CombinedOutput(); err != nil {
		return fmt.Errorf("mount %s: %w: %s", image, err, out)
	}
	defer exec.Command("umount", mnt).Run()
	return fn(mnt)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
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
		if d.IsDir() && d.Name() == "lost+found" {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(path, target)
	})
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
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
