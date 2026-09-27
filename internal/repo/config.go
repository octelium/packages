package repo

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	URL     string                     `json:"url"`
	Name    string                     `json:"name"`
	Title   string                     `json:"title"`
	UID     string                     `json:"uid"`
	Retain  int                        `json:"retain"`
	Grace   Duration                   `json:"grace"`
	GitHub  []string                   `json:"github"`
	Formats map[string]json.RawMessage `json:"formats"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	githubRe = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
)

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{Grace: Duration{72 * time.Hour}}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if u, err := url.Parse(c.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%s: url must be an absolute http(s) URL", path)
	}
	if !nameRe.MatchString(c.Name) {
		return nil, fmt.Errorf("%s: name must match %s", path, nameRe)
	}
	if c.Title == "" || strings.ContainsAny(c.Title, "\n[]") {
		return nil, fmt.Errorf("%s: title is required and must be a single line", path)
	}
	if c.UID == "" || strings.Contains(c.UID, "\n") {
		return nil, fmt.Errorf("%s: uid is required", path)
	}
	if c.Retain < 0 || c.Grace.Duration < 0 {
		return nil, fmt.Errorf("%s: retain and grace must not be negative", path)
	}
	for _, r := range c.GitHub {
		if !githubRe.MatchString(r) {
			return nil, fmt.Errorf("%s: invalid GitHub repository %q", path, r)
		}
	}
	if len(c.Formats) == 0 {
		return nil, fmt.Errorf("%s: at least one format is required", path)
	}
	return c, nil
}
