package rpm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/octelium/packages/internal/pgp"
	"github.com/octelium/packages/internal/repo"
)

const (
	tagName          = 1000
	tagVersion       = 1001
	tagRelease       = 1002
	tagEpoch         = 1003
	tagArch          = 1022
	tagSourcePackage = 1106

	typeInt32  = 4
	typeString = 6
)

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._+~^]+$`)
	archRe    = regexp.MustCompile(`^[a-z0-9_]+$`)
	unsafeRe  = regexp.MustCompile(`[\s'"%\\]`)
)

type Format struct{}

func New(raw json.RawMessage) (repo.Format, error) {
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&struct{}{}); err != nil {
			return nil, fmt.Errorf("rpm: %w", err)
		}
	}
	return &Format{}, nil
}

func (f *Format) Name() string {
	return "rpm"
}

func (f *Format) Root() string {
	return "rpm"
}

func (f *Format) Match(filename string) bool {
	return strings.HasSuffix(filename, ".rpm")
}

func (f *Format) Compare(a, b string) int {
	return CompareEVR(a, b)
}

func (f *Format) Inspect(_ *repo.Env, file string) (*repo.Package, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	r := bufio.NewReader(fh)

	lead := make([]byte, 96)
	if _, err := io.ReadFull(r, lead); err != nil || !bytes.Equal(lead[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, fmt.Errorf("not an RPM package")
	}
	if binary.BigEndian.Uint16(lead[6:8]) != 0 {
		return nil, fmt.Errorf("source RPMs are not supported")
	}
	if _, err := readHeader(r, true); err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	h := sha256.New()
	hdr, err := readHeader(io.TeeReader(r, h), false)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	if _, ok := hdr.entry(tagSourcePackage); ok {
		return nil, fmt.Errorf("source RPMs are not supported")
	}

	name, version, release, arch := hdr.str(tagName), hdr.str(tagVersion), hdr.str(tagRelease), hdr.str(tagArch)
	switch {
	case !nameRe.MatchString(name):
		return nil, fmt.Errorf("invalid package name %q", name)
	case !versionRe.MatchString(version) || !versionRe.MatchString(release):
		return nil, fmt.Errorf("invalid version %q-%q", version, release)
	case !archRe.MatchString(arch):
		return nil, fmt.Errorf("invalid architecture %q", arch)
	}
	evr := version + "-" + release
	if epoch, ok := hdr.int32(tagEpoch); ok && epoch != 0 {
		evr = strconv.Itoa(int(epoch)) + ":" + evr
	}
	return &repo.Package{
		Format:  "rpm",
		Name:    name,
		Version: evr,
		Arch:    arch,
		Path:    path.Join("rpm/Packages", strings.ToLower(name[:1]), name+"-"+version+"-"+release+"."+arch+".rpm"),
		ID:      hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func (f *Format) Prepare(ctx context.Context, env *repo.Env, files []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "rpmsign-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	wrapper := filepath.Join(dir, "gpg")
	if unsafeRe.MatchString(wrapper) {
		return fmt.Errorf("the temporary directory must not contain whitespace, quotes or %%")
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %s gpg --key %s -- \"$@\"\n", shellQuote(exe), shellQuote(env.KeySpec))
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		return err
	}
	fpr := env.Key.Fingerprint()
	args := []string{
		"--define", "__gpg " + wrapper,
		"--define", "_gpg_name " + fpr,
		"--define", "_openpgp_sign_id " + fpr,
		"--define", "_openpgp_sign gpg",
		"--addsign",
	}
	cmd := exec.CommandContext(ctx, "rpmsign", append(args, files...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("rpmsign: %w\n%s", err, out)
	}
	return verify(ctx, env.Key, files)
}

func verify(ctx context.Context, key *pgp.Key, files []string) error {
	dir, err := os.MkdirTemp("", "rpmdb-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	pub, err := key.PublicKey()
	if err != nil {
		return err
	}
	asc := filepath.Join(dir, "key.asc")
	if err := os.WriteFile(asc, pgp.Armor("PGP PUBLIC KEY BLOCK", pub), 0o644); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "rpmkeys", "--dbpath", dir, "--import", asc).CombinedOutput(); err != nil {
		return fmt.Errorf("rpmkeys --import: %w\n%s", err, out)
	}
	out, err := exec.CommandContext(ctx, "rpmkeys", append([]string{"--dbpath", dir, "--checksig"}, files...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rpmkeys --checksig: %w\n%s", err, out)
	}
	for _, file := range files {
		ok := false
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, file+":") && strings.Contains(line, "signatures OK") {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s: signature verification failed\n%s", file, out)
		}
	}
	return nil
}

func (f *Format) Build(ctx context.Context, env *repo.Env, pkgs []*repo.Package, out *repo.Output) error {
	dir := out.Path("rpm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "createrepo_c",
		"--no-database",
		"--general-compress-type", "gz",
		"--checksum", "sha256",
		"--repomd-checksum", "sha256",
		"--unique-md-filenames",
		"--revision", strconv.FormatInt(env.Time.Unix(), 10),
		"--set-timestamp-to-revision",
		dir,
	)
	if o, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("createrepo_c: %w\n%s", err, o)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "repodata"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != "repomd.xml" {
			if err := out.Add("rpm/repodata/"+e.Name(), repo.Immutable); err != nil {
				return err
			}
		}
	}
	pub, err := env.Key.PublicKey()
	if err != nil {
		return err
	}
	if err := out.Write("rpm/repodata/repomd.xml.key", pgp.Armor("PGP PUBLIC KEY BLOCK", pub), repo.Index); err != nil {
		return err
	}
	repomd, err := os.ReadFile(filepath.Join(dir, "repodata", "repomd.xml"))
	if err != nil {
		return err
	}
	sig, err := env.Key.ArmoredSign(bytes.NewReader(repomd), time.Now())
	if err != nil {
		return err
	}
	if err := out.Add("rpm/repodata/repomd.xml", repo.Head); err != nil {
		return err
	}
	if err := out.Write("rpm/repodata/repomd.xml.asc", sig, repo.Head); err != nil {
		return err
	}

	c := env.Config
	conf := fmt.Sprintf("[%s]\nname=%s\nbaseurl=%s/rpm\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=%s/keys/%s.asc\ntype=rpm-md\nautorefresh=1\n",
		c.Name, c.Title, c.URL, c.URL, c.Name)
	return out.Write("rpm/"+c.Name+".repo", []byte(conf), repo.Index)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

type header struct {
	index []byte
	store []byte
}

func readHeader(r io.Reader, pad bool) (*header, error) {
	intro := make([]byte, 16)
	if _, err := io.ReadFull(r, intro); err != nil {
		return nil, err
	}
	if !bytes.Equal(intro[:4], []byte{0x8e, 0xad, 0xe8, 0x01}) {
		return nil, fmt.Errorf("bad header magic")
	}
	il, dl := binary.BigEndian.Uint32(intro[8:12]), binary.BigEndian.Uint32(intro[12:16])
	if il > 0xffff || dl > 256<<20 {
		return nil, fmt.Errorf("header too large")
	}
	buf := make([]byte, 16*int(il)+int(dl))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	if pad {
		if _, err := io.CopyN(io.Discard, r, int64((8-dl%8)%8)); err != nil {
			return nil, err
		}
	}
	return &header{index: buf[:16*il], store: buf[16*il:]}, nil
}

func (h *header) entry(tag uint32) ([]byte, bool) {
	for i := 0; i+16 <= len(h.index); i += 16 {
		e := h.index[i : i+16]
		if binary.BigEndian.Uint32(e) == tag {
			return e, true
		}
	}
	return nil, false
}

func (h *header) str(tag uint32) string {
	e, ok := h.entry(tag)
	if !ok || binary.BigEndian.Uint32(e[4:]) != typeString {
		return ""
	}
	off := int(binary.BigEndian.Uint32(e[8:]))
	if off >= len(h.store) {
		return ""
	}
	s, _, _ := bytes.Cut(h.store[off:], []byte{0})
	return string(s)
}

func (h *header) int32(tag uint32) (int32, bool) {
	e, ok := h.entry(tag)
	if !ok || binary.BigEndian.Uint32(e[4:]) != typeInt32 {
		return 0, false
	}
	off := int(binary.BigEndian.Uint32(e[8:]))
	if off+4 > len(h.store) {
		return 0, false
	}
	return int32(binary.BigEndian.Uint32(h.store[off:])), true
}
