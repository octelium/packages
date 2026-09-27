package repo_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/octelium/packages/internal/deb"
	"github.com/octelium/packages/internal/pgp"
	"github.com/octelium/packages/internal/repo"
	"github.com/octelium/packages/internal/storage"
	"github.com/octelium/packages/internal/testutil"
)

type fixture struct {
	t      *testing.T
	root   string
	inputs string
	key    *pgp.Key
	config *repo.Config
}

func newFixture(t *testing.T) *fixture {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pgp.New(priv, time.Now().Add(-time.Hour), "Test <test@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		t:      t,
		root:   t.TempDir(),
		inputs: t.TempDir(),
		key:    key,
		config: &repo.Config{
			URL:     "https://packages.example.com",
			Name:    "example",
			Title:   "Example",
			UID:     "Test <test@example.com>",
			Retain:  2,
			Grace:   repo.Duration{Duration: time.Hour},
			Formats: map[string]json.RawMessage{"deb": nil},
		},
	}
}

func (f *fixture) publish(files ...string) error {
	format, err := deb.New(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	p := &repo.Publisher{
		Config:  f.config,
		Store:   &storage.FS{Root: f.root},
		Formats: []repo.Format{format},
		Key:     f.key,
		Work:    f.t.TempDir(),
	}
	return p.Run(f.t.Context(), files, nil)
}

func (f *fixture) manifest() *repo.Manifest {
	data, err := os.ReadFile(filepath.Join(f.root, "manifest.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	m := &repo.Manifest{}
	if err := json.Unmarshal(data, m); err != nil {
		f.t.Fatal(err)
	}
	return m
}

func (f *fixture) exists(key string) bool {
	_, err := os.Stat(filepath.Join(f.root, key))
	return err == nil
}

func TestPublishLifecycle(t *testing.T) {
	f := newFixture(t)

	if err := f.publish(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"deb/dists/stable/InRelease", "deb/dists/stable/main/binary-arm64/Packages", "keys/example.asc", "keys/example.gpg", "deb/example.sources"} {
		if !f.exists(key) {
			t.Fatalf("%s was not published", key)
		}
	}

	v1 := testutil.Deb(t, f.inputs, "example", "1.0-1", "amd64", "zst", "")
	all := testutil.Deb(t, f.inputs, "example-data", "1.0", "all", "gz", "")
	if err := f.publish(v1, all); err != nil {
		t.Fatal(err)
	}
	m := f.manifest()
	if len(m.Packages) != 2 || m.Key != f.key.Fingerprint() {
		t.Fatalf("unexpected manifest %+v", m)
	}
	updated := m.Updated
	arm64, _ := os.ReadFile(filepath.Join(f.root, "deb/dists/stable/main/binary-arm64/Packages"))
	if !strings.Contains(string(arm64), "Package: example-data\n") || strings.Contains(string(arm64), "Package: example\n") {
		t.Fatalf("unexpected arm64 index:\n%s", arm64)
	}

	time.Sleep(1100 * time.Millisecond)
	if err := f.publish(f.inputs); err != nil {
		t.Fatal(err)
	}
	if !f.manifest().Updated.Equal(updated) {
		t.Fatal("republishing identical packages changed the repository")
	}

	conflict := testutil.Deb(t, t.TempDir(), "example", "1.0-1", "amd64", "gz", "Section: net\n")
	if err := f.publish(conflict); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("expected conflict, got %v", err)
	}

	byHash := filepath.Join(f.root, "deb/dists/stable/main/binary-amd64/by-hash/SHA256")
	before, _ := os.ReadDir(byHash)

	v2 := testutil.Deb(t, f.inputs, "example", "1.0-2", "amd64", "zst", "")
	v10 := testutil.Deb(t, f.inputs, "example", "1.0-10", "amd64", "zst", "")
	if err := f.publish(v2, v10); err != nil {
		t.Fatal(err)
	}
	m = f.manifest()
	var versions []string
	for _, pkg := range m.Packages {
		if pkg.Name == "example" {
			versions = append(versions, pkg.Version)
		}
	}
	if strings.Join(versions, " ") != "1.0-10 1.0-2" {
		t.Fatalf("unexpected retained versions %v", versions)
	}
	old := "deb/pool/main/e/example/example_1.0-1_amd64.deb"
	if _, ok := m.Retired[old]; !ok || !f.exists(old) {
		t.Fatalf("%s should be retired but still present", old)
	}
	for _, e := range before {
		key := "deb/dists/stable/main/binary-amd64/by-hash/SHA256/" + e.Name()
		if !f.exists(key) {
			t.Fatalf("%s was deleted before its grace period", key)
		}
	}

	f.config.Grace = repo.Duration{}
	v11 := testutil.Deb(t, f.inputs, "example", "1.0-11", "amd64", "zst", "")
	if err := f.publish(v11); err != nil {
		t.Fatal(err)
	}
	if f.exists(old) {
		t.Fatalf("%s should have been deleted", old)
	}
	if _, ok := f.manifest().Retired[old]; ok {
		t.Fatal("deleted object is still tracked")
	}
	amd64, _ := os.ReadFile(filepath.Join(f.root, "deb/dists/stable/main/binary-amd64/Packages"))
	if strings.Contains(string(amd64), "Version: 1.0-2\n") || !strings.Contains(string(amd64), "Version: 1.0-11\n") {
		t.Fatalf("unexpected amd64 index:\n%s", amd64)
	}

	updated = f.manifest().Updated
	time.Sleep(1100 * time.Millisecond)
	if err := f.publish(v1); err != nil {
		t.Fatal(err)
	}
	if !f.manifest().Updated.Equal(updated) || f.exists(old) {
		t.Fatal("publishing a version older than the retained ones changed the repository")
	}
}

func TestPublishRejectsKeyChange(t *testing.T) {
	f := newFixture(t)
	if err := f.publish(); err != nil {
		t.Fatal(err)
	}
	g := newFixture(t)
	f.key = g.key
	if err := f.publish(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected key mismatch error, got %v", err)
	}
}

func TestPublishAdoptsUnrecordedUploads(t *testing.T) {
	f := newFixture(t)
	v1 := testutil.Deb(t, f.inputs, "example", "1.0-1", "amd64", "gz", "")
	if err := f.publish(v1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.root, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if err := f.publish(v1); err != nil {
		t.Fatal(err)
	}
	if len(f.manifest().Packages) != 1 {
		t.Fatal("package was not adopted")
	}

	if err := os.Remove(filepath.Join(f.root, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	other := testutil.Deb(t, t.TempDir(), "example", "1.0-1", "amd64", "zst", "")
	if err := f.publish(other); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("expected conflict with unrecorded upload, got %v", err)
	}
}
