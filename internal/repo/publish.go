package repo

import (
	"cmp"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/octelium/packages/internal/pgp"
	"github.com/octelium/packages/internal/storage"
)

const (
	cacheImmutable = "public, max-age=31536000, immutable"
	cacheMutable   = "no-cache"
	parallelism    = 8
)

type Publisher struct {
	Config  *Config
	Store   storage.Storage
	Formats []Format
	Key     *pgp.Key
	KeySpec string
	Work    string
	DryRun  bool
	Rebuild bool
}

type candidate struct {
	pkg     *Package
	format  Format
	file    string
	adopted bool
}

func (p *Publisher) Run(ctx context.Context, files, refs []string) error {
	for _, dir := range []string{"inputs", "out"} {
		if err := os.RemoveAll(filepath.Join(p.Work, dir)); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(p.Work, 0o755); err != nil {
		return err
	}

	m, err := loadManifest(ctx, p.Store, p.Work)
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}
	fresh := m == nil
	if fresh {
		m = &Manifest{}
		log.Printf("no manifest found, initializing a new repository")
	}
	if m.Key != "" && m.Key != p.Key.Fingerprint() {
		return fmt.Errorf("signing key %s does not match the repository key %s", p.Key.Fingerprint(), m.Key)
	}

	now := time.Now().UTC().Truncate(time.Second)
	env := &Env{Config: p.Config, Key: p.Key, KeySpec: p.KeySpec, Time: now}

	sources := map[string]string{}
	var releases []*release
	for _, ref := range refs {
		rel, err := p.githubRelease(ctx, ref)
		if err != nil {
			return err
		}
		if m.hasSource(rel.repo, rel.tag) {
			log.Printf("%s@%s is already published", rel.repo, rel.tag)
			continue
		}
		releases = append(releases, rel)
		for _, a := range rel.assets {
			if p.formatFor(a.name) == nil {
				continue
			}
			log.Printf("downloading %s from %s@%s", a.name, rel.repo, rel.tag)
			file, err := p.downloadAsset(ctx, rel, a)
			if err != nil {
				return err
			}
			files = append(files, file)
			sources[file] = "github.com/" + rel.repo + "@" + rel.tag
		}
	}

	inputs, err := p.expand(files)
	if err != nil {
		return err
	}

	byPath := map[string]*Package{}
	for _, pkg := range m.Packages {
		if p.format(pkg.Format) == nil {
			return fmt.Errorf("the repository contains %s packages but the %s format is not configured", pkg.Format, pkg.Format)
		}
		byPath[pkg.Path] = pkg
	}
	var added []*candidate
	for _, file := range inputs {
		f := p.formatFor(file)
		pkg, err := f.Inspect(env, file)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if existing, ok := byPath[pkg.Path]; ok {
			if existing.ID != pkg.ID {
				return fmt.Errorf("%s: %s is already published with different content", file, pkg.Path)
			}
			log.Printf("%s is already published", pkg.Path)
			continue
		}
		pkg.Added = now
		pkg.Source = sources[file]
		byPath[pkg.Path] = pkg
		added = append(added, &candidate{pkg: pkg, format: f, file: file})
	}

	all := slices.Clone(m.Packages)
	for _, c := range added {
		all = append(all, c.pkg)
	}
	kept, pruned := p.retain(all)
	var removed []*Package
	for _, pkg := range pruned {
		if slices.ContainsFunc(added, func(c *candidate) bool { return c.pkg == pkg }) {
			log.Printf("skipping %s, newer versions are retained", pkg.Path)
			continue
		}
		log.Printf("retiring %s", pkg.Path)
		removed = append(removed, pkg)
	}
	added = slices.DeleteFunc(added, func(c *candidate) bool { return slices.Contains(pruned, c.pkg) })

	if len(added) == 0 && len(removed) == 0 && !fresh && !p.Rebuild {
		log.Printf("nothing to publish")
		if len(releases) == 0 || p.DryRun {
			return nil
		}
		recordSources(m, releases)
		return p.saveManifest(ctx, m)
	}

	slices.SortFunc(kept, func(a, b *Package) int { return strings.Compare(a.Path, b.Path) })
	m.Packages = kept
	m.Key = p.Key.Fingerprint()
	m.Updated = now

	remote := map[string]storage.Object{}
	roots := []string{"keys/"}
	for _, f := range p.Formats {
		roots = append(roots, f.Root()+"/")
	}
	for _, root := range roots {
		objects, err := p.Store.List(ctx, root)
		if err != nil {
			return fmt.Errorf("listing %s: %w", root, err)
		}
		for _, o := range objects {
			remote[o.Key] = o
		}
	}

	out := &Output{Dir: filepath.Join(p.Work, "out")}
	if err := p.materialize(ctx, env, kept, added, remote, out); err != nil {
		return err
	}

	for _, f := range p.Formats {
		var pkgs []*Package
		for _, pkg := range kept {
			if pkg.Format == f.Name() {
				pkgs = append(pkgs, pkg)
			}
		}
		slices.SortFunc(pkgs, func(a, b *Package) int {
			return cmp.Or(strings.Compare(a.Name, b.Name), f.Compare(a.Version, b.Version), strings.Compare(a.Arch, b.Arch))
		})
		if err := f.Build(ctx, env, pkgs, out); err != nil {
			return fmt.Errorf("building %s metadata: %w", f.Name(), err)
		}
	}
	pub, err := p.Key.PublicKey()
	if err != nil {
		return err
	}
	if err := out.Write("keys/"+p.Config.Name+".asc", pgp.Armor("PGP PUBLIC KEY BLOCK", pub), Index); err != nil {
		return err
	}
	if err := out.Write("keys/"+p.Config.Name+".gpg", pub, Index); err != nil {
		return err
	}

	if p.DryRun {
		log.Printf("dry run: %d added, %d retired, output in %s", len(added), len(removed), out.Dir)
		return nil
	}
	if err := p.upload(ctx, out, added, remote); err != nil {
		return err
	}
	if err := p.collect(ctx, m, out, remote, now); err != nil {
		return err
	}
	recordSources(m, releases)
	if err := p.saveManifest(ctx, m); err != nil {
		return err
	}
	log.Printf("published %d packages (%d added, %d retired)", len(kept), len(added), len(removed))
	return nil
}

func (p *Publisher) formatFor(name string) Format {
	for _, f := range p.Formats {
		if f.Match(name) {
			return f
		}
	}
	return nil
}

func (p *Publisher) format(name string) Format {
	for _, f := range p.Formats {
		if f.Name() == name {
			return f
		}
	}
	return nil
}

func (p *Publisher) expand(args []string) ([]string, error) {
	var files []string
	for _, arg := range args {
		st, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			if p.formatFor(arg) == nil {
				return nil, fmt.Errorf("%s: unsupported package type", arg)
			}
			files = append(files, arg)
			continue
		}
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() && p.formatFor(path) != nil {
				files = append(files, path)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func (p *Publisher) retain(pkgs []*Package) (kept, removed []*Package) {
	if p.Config.Retain == 0 {
		return pkgs, nil
	}
	groups := map[string][]*Package{}
	for _, pkg := range pkgs {
		k := pkg.Format + "\x00" + pkg.Name + "\x00" + pkg.Arch
		groups[k] = append(groups[k], pkg)
	}
	for _, group := range groups {
		f := p.format(group[0].Format)
		slices.SortFunc(group, func(a, b *Package) int { return f.Compare(b.Version, a.Version) })
		for i, pkg := range group {
			if i < p.Config.Retain {
				kept = append(kept, pkg)
			} else {
				removed = append(removed, pkg)
			}
		}
	}
	return kept, removed
}

func (p *Publisher) materialize(ctx context.Context, env *Env, kept []*Package, added []*candidate, remote map[string]storage.Object, out *Output) error {
	isNew := map[*Package]*candidate{}
	for _, c := range added {
		isNew[c.pkg] = c
	}
	var existing []*Package
	for _, pkg := range kept {
		if isNew[pkg] == nil {
			existing = append(existing, pkg)
		}
	}
	err := parallel(existing, func(pkg *Package) error {
		src, err := p.fetch(ctx, pkg)
		if err != nil {
			return err
		}
		return link(src, out.Path(pkg.Path))
	})
	if err != nil {
		return err
	}

	for _, c := range added {
		if _, ok := remote[c.pkg.Path]; ok {
			cached := filepath.Join(p.Work, "cache", filepath.FromSlash(c.pkg.Path))
			if err := p.Store.Get(ctx, c.pkg.Path, cached); err != nil {
				return err
			}
			orphan, err := c.format.Inspect(env, cached)
			if err != nil {
				return fmt.Errorf("unpublished object %s: %w", c.pkg.Path, err)
			}
			if orphan.ID != c.pkg.ID {
				return fmt.Errorf("%s: unpublished object %s exists with different content", c.file, c.pkg.Path)
			}
			log.Printf("adopting previously uploaded %s", c.pkg.Path)
			c.adopted = true
			if err := link(cached, out.Path(c.pkg.Path)); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(c.file, out.Path(c.pkg.Path)); err != nil {
			return err
		}
	}

	for _, f := range p.Formats {
		var files []string
		for _, c := range added {
			if c.format == f && !c.adopted {
				files = append(files, out.Path(c.pkg.Path))
			}
		}
		if len(files) == 0 {
			continue
		}
		if err := f.Prepare(ctx, env, files); err != nil {
			return fmt.Errorf("preparing %s packages: %w", f.Name(), err)
		}
	}

	for _, c := range added {
		file := out.Path(c.pkg.Path)
		check, err := c.format.Inspect(env, file)
		if err != nil {
			return err
		}
		if check.ID != c.pkg.ID || check.Path != c.pkg.Path {
			return fmt.Errorf("%s changed identity while being prepared", c.pkg.Path)
		}
		if c.pkg.Size, c.pkg.SHA256, err = digest(file); err != nil {
			return err
		}
	}
	for _, pkg := range kept {
		if err := os.Chtimes(out.Path(pkg.Path), pkg.Added, pkg.Added); err != nil {
			return err
		}
	}
	return nil
}

func (p *Publisher) fetch(ctx context.Context, pkg *Package) (string, error) {
	cached := filepath.Join(p.Work, "cache", filepath.FromSlash(pkg.Path))
	if size, sum, err := digest(cached); err == nil && size == pkg.Size && sum == pkg.SHA256 {
		return cached, nil
	}
	log.Printf("fetching %s", pkg.Path)
	if err := p.Store.Get(ctx, pkg.Path, cached); err != nil {
		return "", fmt.Errorf("fetching %s: %w", pkg.Path, err)
	}
	size, sum, err := digest(cached)
	if err != nil {
		return "", err
	}
	if size != pkg.Size || sum != pkg.SHA256 {
		return "", fmt.Errorf("%s does not match the manifest (sha256 %s, expected %s)", pkg.Path, sum, pkg.SHA256)
	}
	return cached, nil
}

func (p *Publisher) upload(ctx context.Context, out *Output, added []*candidate, remote map[string]storage.Object) error {
	put := func(key string, class Class) error {
		local := out.Path(key)
		st, err := os.Stat(local)
		if err != nil {
			return err
		}
		if r, ok := remote[key]; ok && r.Size == st.Size() {
			if class == Pool || class == Immutable {
				return nil
			}
			if r.ETag != "" {
				sum, err := md5File(local)
				if err != nil {
					return err
				}
				if sum == r.ETag {
					return nil
				}
			}
		}
		cache := cacheMutable
		if class == Pool || class == Immutable {
			cache = cacheImmutable
		}
		log.Printf("uploading %s", key)
		if err := p.Store.Put(ctx, key, local, contentType(key), cache); err != nil {
			return fmt.Errorf("uploading %s: %w", key, err)
		}
		return nil
	}

	err := parallel(added, func(c *candidate) error { return put(c.pkg.Path, Pool) })
	if err != nil {
		return err
	}
	for _, class := range []Class{Immutable, Index, Head} {
		var files []OutputFile
		for _, f := range out.Files {
			if f.Class == class {
				files = append(files, f)
			}
		}
		if class == Immutable {
			err = parallel(files, func(f OutputFile) error { return put(f.Key, class) })
			if err != nil {
				return err
			}
			continue
		}
		for _, f := range files {
			if err := put(f.Key, class); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Publisher) collect(ctx context.Context, m *Manifest, out *Output, remote map[string]storage.Object, now time.Time) error {
	referenced := map[string]bool{}
	for _, pkg := range m.Packages {
		referenced[pkg.Path] = true
	}
	for _, f := range out.Files {
		referenced[f.Key] = true
	}
	retired := map[string]time.Time{}
	for key, since := range m.Retired {
		if _, ok := remote[key]; ok && !referenced[key] {
			retired[key] = since
		}
	}
	keys := make([]string, 0, len(remote))
	for key := range remote {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if referenced[key] {
			continue
		}
		since, ok := retired[key]
		if !ok {
			retired[key] = now
			continue
		}
		if now.Sub(since) < p.Config.Grace.Duration {
			continue
		}
		log.Printf("deleting %s", key)
		if err := p.Store.Delete(ctx, key); err != nil {
			return fmt.Errorf("deleting %s: %w", key, err)
		}
		delete(retired, key)
	}
	m.Retired = retired
	return nil
}

func (p *Publisher) saveManifest(ctx context.Context, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	file := filepath.Join(p.Work, manifestKey)
	if err := os.WriteFile(file, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return p.Store.Put(ctx, manifestKey, file, "application/json", cacheMutable)
}

func recordSources(m *Manifest, releases []*release) {
	if len(releases) > 0 && m.Sources == nil {
		m.Sources = map[string][]string{}
	}
	for _, rel := range releases {
		if !m.hasSource(rel.repo, rel.tag) {
			m.Sources[rel.repo] = append(m.Sources[rel.repo], rel.tag)
		}
	}
}

func contentType(key string) string {
	base := path.Base(key)
	switch {
	case base == "Release.gpg" || strings.HasSuffix(base, ".xml.asc"):
		return "application/pgp-signature"
	case strings.HasSuffix(base, ".asc") || strings.HasSuffix(base, ".gpg") || strings.HasSuffix(base, ".key"):
		return "application/pgp-keys"
	case base == "InRelease" || base == "Release" || base == "Packages" || strings.HasSuffix(base, ".repo") || strings.HasSuffix(base, ".sources"):
		return "text/plain; charset=utf-8"
	}
	switch path.Ext(base) {
	case ".deb":
		return "application/vnd.debian.binary-package"
	case ".rpm":
		return "application/x-rpm"
	case ".gz":
		return "application/gzip"
	case ".xml":
		return "application/xml"
	case ".json":
		return "application/json"
	}
	return "application/octet-stream"
}

func parallel[T any](items []T, fn func(T) error) error {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	sem := make(chan struct{}, parallelism)
	for _, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(item); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func digest(file string) (int64, string, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func md5File(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func link(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
