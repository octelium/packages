package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrNotExist = errors.New("object does not exist")

type Object struct {
	Key      string
	Size     int64
	ETag     string
	Modified time.Time
}

type Storage interface {
	List(ctx context.Context, prefix string) ([]Object, error)
	Get(ctx context.Context, key, dst string) error
	Put(ctx context.Context, key, src, contentType, cacheControl string) error
	Delete(ctx context.Context, key string) error
}

func Open(ctx context.Context, url string) (Storage, error) {
	scheme, rest, ok := strings.Cut(url, "://")
	if !ok || rest == "" {
		return nil, fmt.Errorf("invalid storage %q", url)
	}
	switch scheme {
	case "file":
		return &FS{Root: rest}, nil
	case "r2":
		return openR2(rest)
	case "s3":
		return openS3(ctx, rest)
	default:
		return nil, fmt.Errorf("unsupported storage scheme %q", scheme)
	}
}

func writeFile(dst string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

type FS struct {
	Root string
}

func (s *FS) List(_ context.Context, prefix string) ([]Object, error) {
	var objects []Object
	err := filepath.WalkDir(s.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".download-") {
			return nil
		}
		rel, err := filepath.Rel(s.Root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		objects = append(objects, Object{Key: key, Size: info.Size(), Modified: info.ModTime()})
		return nil
	})
	return objects, err
}

func (s *FS) Get(_ context.Context, key, dst string) error {
	f, err := os.Open(filepath.Join(s.Root, filepath.FromSlash(key)))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotExist
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return writeFile(dst, f)
}

func (s *FS) Put(_ context.Context, key, src, _, _ string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeFile(filepath.Join(s.Root, filepath.FromSlash(key)), f)
}

func (s *FS) Delete(_ context.Context, key string) error {
	err := os.Remove(filepath.Join(s.Root, filepath.FromSlash(key)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
