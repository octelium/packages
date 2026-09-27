package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type release struct {
	repo   string
	tag    string
	assets []asset
}

type asset struct {
	name   string
	url    string
	size   int64
	digest string
}

var (
	githubClient = &http.Client{Timeout: 15 * time.Minute}
	assetNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)
	tagRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

func (p *Publisher) githubRelease(ctx context.Context, ref string) (*release, error) {
	repo, tag, pinned := strings.Cut(ref, "@")
	if !slices.Contains(p.Config.GitHub, repo) {
		return nil, fmt.Errorf("GitHub repository %s is not listed in the configuration", repo)
	}
	endpoint := "https://api.github.com/repos/" + repo + "/releases/latest"
	if pinned {
		if !tagRe.MatchString(tag) {
			return nil, fmt.Errorf("invalid tag %q", tag)
		}
		endpoint = "https://api.github.com/repos/" + repo + "/releases/tags/" + url.PathEscape(tag)
	}
	resp, err := githubGet(ctx, endpoint, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			Size   int64  `json:"size"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	if r.Draft || r.Prerelease {
		return nil, fmt.Errorf("%s@%s is a draft or prerelease", repo, r.TagName)
	}
	if !tagRe.MatchString(r.TagName) {
		return nil, fmt.Errorf("%s has an invalid tag %q", repo, r.TagName)
	}
	rel := &release{repo: repo, tag: r.TagName}
	for _, a := range r.Assets {
		rel.assets = append(rel.assets, asset{name: a.Name, url: a.URL, size: a.Size, digest: a.Digest})
	}
	return rel, nil
}

func (p *Publisher) downloadAsset(ctx context.Context, rel *release, a asset) (string, error) {
	if !assetNameRe.MatchString(a.name) {
		return "", fmt.Errorf("unsafe asset name %q", a.name)
	}
	dst := filepath.Join(p.Work, "inputs", filepath.FromSlash(rel.repo), rel.tag, a.name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	resp, err := githubGet(ctx, a.url, "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", a.name, err)
	}
	if n != a.size {
		return "", fmt.Errorf("%s: downloaded %d bytes, expected %d", a.name, n, a.size)
	}
	if a.digest != "" {
		if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != a.digest {
			return "", fmt.Errorf("%s: digest %s does not match %s", a.name, got, a.digest)
		}
	}
	return dst, nil
}

func githubGet(ctx context.Context, endpoint, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := githubClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}
