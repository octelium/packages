package repo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/octelium/packages/internal/pgp"
)

type Package struct {
	Format  string    `json:"format"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Arch    string    `json:"arch"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	SHA256  string    `json:"sha256"`
	ID      string    `json:"id"`
	Added   time.Time `json:"added"`
	Source  string    `json:"source,omitempty"`
}

type Env struct {
	Config  *Config
	Key     *pgp.Key
	KeySpec string
	Time    time.Time
}

type Format interface {
	Name() string
	Root() string
	Match(filename string) bool
	Inspect(env *Env, file string) (*Package, error)
	Compare(a, b string) int
	Prepare(ctx context.Context, env *Env, files []string) error
	Build(ctx context.Context, env *Env, pkgs []*Package, out *Output) error
}

type Class int

const (
	Pool Class = iota
	Immutable
	Index
	Head
)

type Output struct {
	Dir   string
	Files []OutputFile
}

type OutputFile struct {
	Key   string
	Class Class
}

func (o *Output) Path(key string) string {
	return filepath.Join(o.Dir, filepath.FromSlash(key))
}

func (o *Output) Write(key string, data []byte, class Class) error {
	path := o.Path(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return o.Add(key, class)
}

func (o *Output) Add(key string, class Class) error {
	for _, f := range o.Files {
		if f.Key == key {
			return fmt.Errorf("duplicate output %s", key)
		}
	}
	o.Files = append(o.Files, OutputFile{Key: key, Class: class})
	return nil
}
