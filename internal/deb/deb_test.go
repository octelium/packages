package deb

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/octelium/packages/internal/pgp"
	"github.com/octelium/packages/internal/repo"
	"github.com/octelium/packages/internal/testutil"
)

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0-0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0.0", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"2.0~", "2.0", -1},
		{"1.0a", "1.0", 1},
		{"1.0+b1", "1.0", 1},
		{"1.0-1~bpo1", "1.0-1", -1},
		{"1:0.1", "2.0", 1},
		{"0.43.0-1", "0.43.1-1", -1},
		{"0.43.0-2", "0.43.0-10", -1},
		{"1.0-1", "1.0-1", 0},
		{"1.0.a", "1.0.+", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestInspectAndBuild(t *testing.T) {
	dir := t.TempDir()
	f, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pgp.New(priv, time.Now().Add(-time.Hour), "Test <test@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	env := &repo.Env{
		Config: &repo.Config{URL: "https://packages.example.com", Name: "example", Title: "Example"},
		Key:    key,
		Time:   time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
	}

	out := &repo.Output{Dir: t.TempDir()}
	var pkgs []*repo.Package
	for _, c := range [][4]string{
		{"example", "1:1.0-1", "amd64", "zst"},
		{"example", "1:1.0-1", "arm64", "xz"},
		{"libexample-data", "1.0", "all", "gz"},
		{"example-riscv", "2.0", "riscv64", "gz"},
	} {
		file := testutil.Deb(t, dir, c[0], c[1], c[2], c[3], "Size: 1\nSHA256: bogus\n")
		pkg, err := f.Inspect(env, file)
		if err != nil {
			t.Fatal(err)
		}
		if pkg.Name != c[0] || pkg.Version != c[1] || pkg.Arch != c[2] {
			t.Fatalf("unexpected package %+v", pkg)
		}
		if strings.Contains(path.Base(pkg.Path), ":") {
			t.Fatalf("epoch in pool path %s", pkg.Path)
		}
		data, _ := os.ReadFile(file)
		sum := sha256.Sum256(data)
		pkg.Size, pkg.SHA256 = int64(len(data)), hex.EncodeToString(sum[:])
		if err := os.MkdirAll(path.Dir(out.Path(pkg.Path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out.Path(pkg.Path), data, 0o644); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, pkg)
	}
	if want := "deb/pool/main/libe/libexample-data/libexample-data_1.0_all.deb"; pkgs[2].Path != want {
		t.Fatalf("unexpected pool path %s, want %s", pkgs[2].Path, want)
	}

	if err := f.Build(t.Context(), env, pkgs, out); err != nil {
		t.Fatal(err)
	}

	amd64, err := os.ReadFile(out.Path("deb/dists/stable/main/binary-amd64/Packages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Package: example\n", "Package: libexample-data\n", "Filename: pool/main/e/example/example_1.0-1_amd64.deb\n", " .\n more\n"} {
		if !strings.Contains(string(amd64), want) {
			t.Errorf("amd64 Packages lacks %q:\n%s", want, amd64)
		}
	}
	for _, bad := range []string{"SHA256: bogus", "Size: 1\n", "arm64", "riscv64"} {
		if strings.Contains(string(amd64), bad) {
			t.Errorf("amd64 Packages contains %q", bad)
		}
	}
	if strings.Count(string(amd64), "\n\n") != 1 {
		t.Errorf("expected two stanzas:\n%s", amd64)
	}

	release, err := os.ReadFile(out.Path("deb/dists/stable/Release"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(release), "Architectures: amd64 arm64 riscv64\n") || !strings.Contains(string(release), "Date: Sun, 27 Sep 2026 12:00:00 UTC\n") {
		t.Fatalf("unexpected Release:\n%s", release)
	}
	sum := sha256.Sum256(amd64)
	line := fmt.Sprintf(" %s %d main/binary-amd64/Packages\n", hex.EncodeToString(sum[:]), len(amd64))
	if !strings.Contains(string(release), line) {
		t.Fatalf("Release lacks %q", line)
	}
	if _, err := os.Stat(out.Path("deb/dists/stable/main/binary-amd64/by-hash/SHA256/" + hex.EncodeToString(sum[:]))); err != nil {
		t.Fatal(err)
	}

	pub, _ := key.PublicKey()
	ring, err := openpgp.ReadKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatal(err)
	}
	inRelease, _ := os.ReadFile(out.Path("deb/dists/stable/InRelease"))
	block, _ := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatal("InRelease is not clearsigned")
	}
	if _, err := block.VerifySignature(ring, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSuffix(string(block.Plaintext), "\n") != strings.TrimSuffix(string(release), "\n") {
		t.Fatal("InRelease content differs from Release")
	}
	detached, _ := os.ReadFile(out.Path("deb/dists/stable/Release.gpg"))
	if _, err := openpgp.CheckArmoredDetachedSignature(ring, bytes.NewReader(release), bytes.NewReader(detached), nil); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsInvalidPackages(t *testing.T) {
	dir := t.TempDir()
	f, _ := New(nil)
	for _, c := range [][3]string{
		{"../evil", "1.0", "amd64"},
		{"Example", "1.0", "amd64"},
		{"example", "1.0/../../x", "amd64"},
		{"example", "v1.0", "amd64"},
		{"example", "1.0", "amd64/../x"},
	} {
		file := testutil.Deb(t, dir, c[0], c[1], c[2], "gz", "")
		if pkg, err := f.Inspect(nil, file); err == nil {
			t.Errorf("accepted %v as %s", c, pkg.Path)
		}
	}
	notDeb := dir + "/bad.deb"
	if err := os.WriteFile(notDeb, []byte("not a deb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Inspect(nil, notDeb); err == nil {
		t.Fatal("expected error for invalid archive")
	}
	if _, err := parseParagraph([]byte("Package: a\n\nPackage: b\n")); err == nil {
		t.Fatal("expected error for multiple paragraphs")
	}
	if _, err := parseParagraph([]byte("Package: a\nPackage: b\n")); err == nil {
		t.Fatal("expected error for duplicate fields")
	}
}
