// Package store persists capsule records as JSON on the local disk.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
)

// Store is a directory of capsule records. Each capsule lives at
// <dir>/<id>/record.json.
type Store struct {
	Dir string
}

// Save writes c, replacing any existing record for the same id.
func (s Store) Save(c capsule.Capsule) error {
	if !capsule.ValidID(c.ID) {
		return fmt.Errorf("invalid capsule id %q", c.ID)
	}
	dir := filepath.Join(s.Dir, c.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(dir, "record.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads one capsule record.
func (s Store) Load(id string) (capsule.Capsule, error) {
	if !capsule.ValidID(id) {
		return capsule.Capsule{}, fmt.Errorf("invalid capsule id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, id, "record.json"))
	if errors.Is(err, os.ErrNotExist) {
		return capsule.Capsule{}, fmt.Errorf("capsule %s not found", id)
	}
	if err != nil {
		return capsule.Capsule{}, err
	}
	var c capsule.Capsule
	if err := json.Unmarshal(data, &c); err != nil {
		return capsule.Capsule{}, err
	}
	return c, nil
}

// List returns every capsule record, oldest first.
func (s Store) List() ([]capsule.Capsule, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var capsules []capsule.Capsule
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, err := s.Load(entry.Name())
		if err != nil {
			return nil, err
		}
		capsules = append(capsules, c)
	}
	sort.Slice(capsules, func(i, j int) bool {
		return capsules[i].CreatedAt.Before(capsules[j].CreatedAt)
	})
	return capsules, nil
}
