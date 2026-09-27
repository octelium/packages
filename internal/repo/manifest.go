package repo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/octelium/packages/internal/storage"
)

const manifestKey = "manifest.json"

type Manifest struct {
	Key      string               `json:"key"`
	Updated  time.Time            `json:"updated"`
	Packages []*Package           `json:"packages"`
	Sources  map[string][]string  `json:"sources,omitempty"`
	Retired  map[string]time.Time `json:"retired,omitempty"`
}

func loadManifest(ctx context.Context, store storage.Storage, dir string) (*Manifest, error) {
	path := filepath.Join(dir, "remote-"+manifestKey)
	err := store.Get(ctx, manifestKey, path)
	if errors.Is(err, storage.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := &Manifest{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manifest) hasSource(repo, tag string) bool {
	for _, t := range m.Sources[repo] {
		if t == tag {
			return true
		}
	}
	return false
}
