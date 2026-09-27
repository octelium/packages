package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/octelium/packages/internal/repo"
)

type Config struct {
	Suite         string   `json:"suite"`
	Component     string   `json:"component"`
	Architectures []string `json:"architectures"`
}

type Format struct {
	cfg Config
}

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionRe = regexp.MustCompile(`^([0-9]+:)?[0-9][A-Za-z0-9.+~-]*$`)
	archRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	suiteRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	fieldRe   = regexp.MustCompile(`^[!-9;-~]+$`)
	generated = []string{"filename", "size", "md5sum", "sha1", "sha256", "sha512"}
)

func New(raw json.RawMessage) (repo.Format, error) {
	cfg := Config{Suite: "stable", Component: "main", Architectures: []string{"amd64", "arm64"}}
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("deb: %w", err)
		}
	}
	if !suiteRe.MatchString(cfg.Suite) || !suiteRe.MatchString(cfg.Component) {
		return nil, fmt.Errorf("deb: invalid suite or component")
	}
	if len(cfg.Architectures) == 0 {
		return nil, fmt.Errorf("deb: at least one architecture is required")
	}
	for _, a := range cfg.Architectures {
		if !archRe.MatchString(a) || a == "all" {
			return nil, fmt.Errorf("deb: invalid architecture %q", a)
		}
	}
	return &Format{cfg: cfg}, nil
}

func (f *Format) Name() string {
	return "deb"
}

func (f *Format) Root() string {
	return "deb"
}

func (f *Format) Match(filename string) bool {
	return strings.HasSuffix(filename, ".deb")
}

func (f *Format) Compare(a, b string) int {
	return CompareVersions(a, b)
}

func (f *Format) Prepare(context.Context, *repo.Env, []string) error {
	return nil
}

func (f *Format) Inspect(_ *repo.Env, file string) (*repo.Package, error) {
	control, err := readControl(file)
	if err != nil {
		return nil, err
	}
	para, err := parseParagraph(control)
	if err != nil {
		return nil, err
	}
	name, version, arch := para.value("Package"), para.value("Version"), para.value("Architecture")
	switch {
	case !nameRe.MatchString(name):
		return nil, fmt.Errorf("invalid package name %q", name)
	case !versionRe.MatchString(version):
		return nil, fmt.Errorf("invalid version %q", version)
	case !archRe.MatchString(arch):
		return nil, fmt.Errorf("invalid architecture %q", arch)
	}
	_, sum, err := hashes(file)
	if err != nil {
		return nil, err
	}
	prefix := name[:1]
	if strings.HasPrefix(name, "lib") && len(name) > 3 {
		prefix = name[:4]
	}
	fileVersion := version
	if _, v, ok := strings.Cut(version, ":"); ok {
		fileVersion = v
	}
	return &repo.Package{
		Format:  "deb",
		Name:    name,
		Version: version,
		Arch:    arch,
		Path:    path.Join("deb/pool", f.cfg.Component, prefix, name, name+"_"+fileVersion+"_"+arch+".deb"),
		ID:      sum,
	}, nil
}

func (f *Format) Build(_ context.Context, env *repo.Env, pkgs []*repo.Package, out *repo.Output) error {
	arches := slices.Clone(f.cfg.Architectures)
	stanzas := make([]string, len(pkgs))
	for i, pkg := range pkgs {
		if pkg.Arch != "all" && !slices.Contains(arches, pkg.Arch) {
			arches = append(arches, pkg.Arch)
		}
		file := out.Path(pkg.Path)
		control, err := readControl(file)
		if err != nil {
			return fmt.Errorf("%s: %w", pkg.Path, err)
		}
		para, err := parseParagraph(control)
		if err != nil {
			return fmt.Errorf("%s: %w", pkg.Path, err)
		}
		md5sum, _, err := hashes(file)
		if err != nil {
			return err
		}
		var b strings.Builder
		for _, fl := range para {
			if !slices.Contains(generated, strings.ToLower(fl.name)) {
				b.WriteString(fl.raw)
			}
		}
		fmt.Fprintf(&b, "Filename: %s\nSize: %d\nMD5sum: %s\nSHA256: %s\n", strings.TrimPrefix(pkg.Path, "deb/"), pkg.Size, md5sum, pkg.SHA256)
		stanzas[i] = b.String()
	}
	slices.Sort(arches)

	type indexFile struct {
		name string
		data []byte
	}
	var index []indexFile
	for _, arch := range arches {
		var b bytes.Buffer
		for i, pkg := range pkgs {
			if pkg.Arch == arch || pkg.Arch == "all" {
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(stanzas[i])
			}
		}
		gz, err := gzipBytes(b.Bytes())
		if err != nil {
			return err
		}
		name := f.cfg.Component + "/binary-" + arch + "/Packages"
		index = append(index, indexFile{name, b.Bytes()}, indexFile{name + ".gz", gz})
	}

	dist := "deb/dists/" + f.cfg.Suite
	var md5s, sha256s strings.Builder
	for _, ix := range index {
		m, s := md5.Sum(ix.data), sha256.Sum256(ix.data)
		fmt.Fprintf(&md5s, " %s %d %s\n", hex.EncodeToString(m[:]), len(ix.data), ix.name)
		fmt.Fprintf(&sha256s, " %s %d %s\n", hex.EncodeToString(s[:]), len(ix.data), ix.name)
		if err := out.Write(dist+"/"+ix.name, ix.data, repo.Index); err != nil {
			return err
		}
		if err := out.Write(dist+"/"+path.Dir(ix.name)+"/by-hash/SHA256/"+hex.EncodeToString(s[:]), ix.data, repo.Immutable); err != nil {
			return err
		}
	}

	title := env.Config.Title
	release := fmt.Sprintf("Origin: %s\nLabel: %s\nSuite: %s\nCodename: %s\nDate: %s\nArchitectures: %s\nComponents: %s\nDescription: %s packages\nAcquire-By-Hash: yes\nMD5Sum:\n%sSHA256:\n%s",
		title, title, f.cfg.Suite, f.cfg.Suite, env.Time.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC"),
		strings.Join(arches, " "), f.cfg.Component, title, md5s.String(), sha256s.String())

	signed := time.Now()
	detached, err := env.Key.ArmoredSign(strings.NewReader(release), signed)
	if err != nil {
		return err
	}
	inline, err := env.Key.ClearSign([]byte(release), signed)
	if err != nil {
		return err
	}
	if err := out.Write(dist+"/Release", []byte(release), repo.Head); err != nil {
		return err
	}
	if err := out.Write(dist+"/Release.gpg", detached, repo.Head); err != nil {
		return err
	}
	if err := out.Write(dist+"/InRelease", inline, repo.Head); err != nil {
		return err
	}

	sources := fmt.Sprintf("Types: deb\nURIs: %s/deb\nSuites: %s\nComponents: %s\nSigned-By: /etc/apt/keyrings/%s.gpg\n",
		env.Config.URL, f.cfg.Suite, f.cfg.Component, env.Config.Name)
	return out.Write("deb/"+env.Config.Name+".sources", []byte(sources), repo.Index)
}

type field struct {
	name string
	raw  string
}

type paragraph []field

func (p paragraph) value(name string) string {
	for _, f := range p {
		if strings.EqualFold(f.name, name) {
			_, v, _ := strings.Cut(f.raw, ":")
			first, _, _ := strings.Cut(v, "\n")
			return strings.TrimSpace(first)
		}
	}
	return ""
}

func parseParagraph(data []byte) (paragraph, error) {
	var p paragraph
	ended := false
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			ended = len(p) > 0
		case ended:
			return nil, fmt.Errorf("control file contains more than one paragraph")
		case strings.HasPrefix(line, "#"):
		case line[0] == ' ' || line[0] == '\t':
			if len(p) == 0 {
				return nil, fmt.Errorf("control file starts with a continuation line")
			}
			p[len(p)-1].raw += line + "\n"
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok || !fieldRe.MatchString(name) || strings.HasPrefix(name, "-") {
				return nil, fmt.Errorf("invalid control line %q", line)
			}
			for _, f := range p {
				if strings.EqualFold(f.name, name) {
					return nil, fmt.Errorf("duplicate control field %s", name)
				}
			}
			p = append(p, field{name: name, raw: name + ":" + value + "\n"})
		}
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("empty control file")
	}
	return p, nil
}

func readControl(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("not a Debian package")
	}
	for i := 0; ; i++ {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, fmt.Errorf("control member not found: %w", err)
		}
		if string(hdr[58:]) != "`\n" {
			return nil, fmt.Errorf("corrupt ar header")
		}
		name := strings.TrimSuffix(strings.TrimRight(string(hdr[:16]), " "), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("corrupt ar member size")
		}
		body := io.LimitReader(r, size)
		switch {
		case i == 0:
			v, err := io.ReadAll(io.LimitReader(body, 16))
			if err != nil || name != "debian-binary" || !strings.HasPrefix(string(v), "2.") {
				return nil, fmt.Errorf("unsupported Debian package format")
			}
		case strings.HasPrefix(name, "control.tar"):
			return extractControl(name, body)
		case strings.HasPrefix(name, "data.tar"):
			return nil, fmt.Errorf("data member precedes control member")
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			return nil, err
		}
		if size%2 == 1 {
			if _, err := r.Discard(1); err != nil {
				return nil, err
			}
		}
	}
}

func extractControl(member string, r io.Reader) ([]byte, error) {
	var tr io.Reader
	switch strings.TrimPrefix(member, "control.tar") {
	case "":
		tr = r
	case ".gz":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		tr = gz
	case ".xz":
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		tr = xr
	case ".zst":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		tr = zr
	default:
		return nil, fmt.Errorf("unsupported control member %s", member)
	}
	t := tar.NewReader(tr)
	for {
		h, err := t.Next()
		if err != nil {
			return nil, fmt.Errorf("control file not found: %w", err)
		}
		if path.Clean(h.Name) == "control" && h.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(t, 1<<20))
		}
	}
}

func hashes(file string) (md5sum, sha256sum string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	m, s := md5.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

func gzipBytes(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
