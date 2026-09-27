package main

import (
	"strings"
	"testing"

	"github.com/octelium/packages/internal/repo"
)

func TestConfig(t *testing.T) {
	cfg, err := repo.LoadConfig("../../config.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range cfg.Formats {
		ctor, ok := formats[name]
		if !ok {
			t.Fatalf("unsupported format %q", name)
		}
		if _, err := ctor(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseGPGArgs(t *testing.T) {
	for _, c := range []struct {
		args          string
		input, output string
		armor         bool
	}{
		{"--no-verbose --no-armor --no-secmem-warning --digest-algo=sha256 -u ABCD -sbo /tmp/sig -- -", "-", "/tmp/sig", false},
		{"--no-verbose --no-armor --no-secmem-warning -u ABCD -sbo /tmp/out -- /tmp/in", "/tmp/in", "/tmp/out", false},
		{"--no-verbose --no-armor -u ABCD -sbo /tmp/sig --digest-algo=sha256 /tmp/in", "/tmp/in", "/tmp/sig", false},
		{"--homedir /tmp/g -u ABCD -sbo /tmp/sig", "-", "/tmp/sig", false},
		{"--armor --detach-sign -o /tmp/sig.asc /tmp/in", "/tmp/in", "/tmp/sig.asc", true},
		{"-absu ABCD -o - /tmp/in", "/tmp/in", "-", true},
	} {
		input, output, armor, err := parseGPGArgs(strings.Fields(c.args))
		if err != nil || input != c.input || output != c.output || armor != c.armor {
			t.Errorf("%q: got %q %q %v %v", c.args, input, output, armor, err)
		}
	}
	for _, args := range []string{"-u ABCD -- /tmp/in", "-sbo", "-sbo /tmp/sig /tmp/a /tmp/b"} {
		if _, _, _, err := parseGPGArgs(strings.Fields(args)); err == nil {
			t.Errorf("%q: expected an error", args)
		}
	}
}
