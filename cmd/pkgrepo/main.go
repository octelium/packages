package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/octelium/packages/internal/deb"
	"github.com/octelium/packages/internal/pgp"
	"github.com/octelium/packages/internal/repo"
	"github.com/octelium/packages/internal/rpm"
	"github.com/octelium/packages/internal/signer"
	"github.com/octelium/packages/internal/storage"
)

var formats = map[string]func(json.RawMessage) (repo.Format, error){
	"deb": deb.New,
	"rpm": rpm.New,
}

const usage = `usage:
  pkgrepo publish --storage URL --key KEY [--config FILE] [--sync] [--github OWNER/REPO[@TAG]]... [--rebuild] [--dry-run] [--work DIR] [PATH]...
  pkgrepo key --key KEY [--config FILE]
  pkgrepo gpg --key KEY -- [-a] [-u ID] -sbo OUTPUT [--] [INPUT]

KEY is awskms:<key-arn> or file:<pem>. URL is r2://<bucket>, s3://<bucket> or file://<dir>.
`

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "publish":
		err = publish(ctx, os.Args[2:])
	case "key":
		err = key(ctx, os.Args[2:])
	case "gpg":
		err = gpg(ctx, os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

type listFlag []string

func (l *listFlag) String() string {
	return strings.Join(*l, ",")
}

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	return fs
}

func publish(ctx context.Context, args []string) error {
	fs := newFlags("publish")
	configPath := fs.String("config", "config.json", "")
	storageURL := fs.String("storage", "", "")
	keySpec := fs.String("key", "", "")
	work := fs.String("work", "", "")
	syncAll := fs.Bool("sync", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	rebuild := fs.Bool("rebuild", false, "")
	var refs listFlag
	fs.Var(&refs, "github", "")
	fs.Parse(args)

	if *storageURL == "" || *keySpec == "" {
		return fmt.Errorf("--storage and --key are required")
	}
	cfg, err := repo.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	store, err := storage.Open(ctx, *storageURL)
	if err != nil {
		return err
	}
	k, err := openKey(ctx, *keySpec, cfg.UID)
	if err != nil {
		return err
	}

	var names []string
	for name := range cfg.Formats {
		names = append(names, name)
	}
	slices.Sort(names)
	var fmts []repo.Format
	for _, name := range names {
		ctor, ok := formats[name]
		if !ok {
			return fmt.Errorf("unsupported format %q", name)
		}
		f, err := ctor(cfg.Formats[name])
		if err != nil {
			return err
		}
		fmts = append(fmts, f)
	}

	if *work == "" {
		dir, err := os.MkdirTemp("", "pkgrepo-")
		if err != nil {
			return err
		}
		if !*dryRun {
			defer os.RemoveAll(dir)
		}
		*work = dir
	}
	if *syncAll {
		refs = append(refs, cfg.GitHub...)
	}

	p := &repo.Publisher{
		Config:  cfg,
		Store:   store,
		Formats: fmts,
		Key:     k,
		KeySpec: *keySpec,
		Work:    *work,
		DryRun:  *dryRun,
		Rebuild: *rebuild,
	}
	return p.Run(ctx, fs.Args(), refs)
}

func key(ctx context.Context, args []string) error {
	fs := newFlags("key")
	configPath := fs.String("config", "config.json", "")
	keySpec := fs.String("key", "", "")
	fs.Parse(args)

	cfg, err := repo.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	k, err := openKey(ctx, *keySpec, cfg.UID)
	if err != nil {
		return err
	}
	pub, err := k.PublicKey()
	if err != nil {
		return err
	}
	log.Printf("fingerprint %s, created %s", k.Fingerprint(), k.Created().Format(time.RFC3339))
	_, err = os.Stdout.Write(pgp.Armor("PGP PUBLIC KEY BLOCK", pub))
	return err
}

func gpg(ctx context.Context, args []string) error {
	fs := newFlags("gpg")
	keySpec := fs.String("key", "", "")
	fs.Parse(args)

	input, output, armor, err := parseGPGArgs(fs.Args())
	if err != nil {
		return err
	}
	k, err := openKey(ctx, *keySpec, "")
	if err != nil {
		return err
	}
	var in io.Reader = os.Stdin
	if input != "-" {
		f, err := os.Open(input)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	var sig []byte
	if armor {
		sig, err = k.ArmoredSign(in, time.Now())
	} else {
		sig, err = k.Sign(in, time.Now())
	}
	if err != nil {
		return err
	}
	if output == "-" {
		_, err = os.Stdout.Write(sig)
		return err
	}
	return os.WriteFile(output, sig, 0o644)
}

func parseGPGArgs(args []string) (input, output string, armor bool, err error) {
	var inputs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			inputs = append(inputs, args[i+1:]...)
			i = len(args)
		case a == "-u" || a == "--local-user" || a == "--homedir" || a == "-o" || a == "--output":
			if i+1 >= len(args) {
				return "", "", false, fmt.Errorf("%s requires a value", a)
			}
			if a == "-o" || a == "--output" {
				output = args[i+1]
			}
			i++
		case a == "-a" || a == "--armor":
			armor = true
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") && len(a) > 1:
			armor = armor || strings.Contains(a, "a")
			if strings.HasSuffix(a, "o") || strings.HasSuffix(a, "u") {
				if i+1 >= len(args) {
					return "", "", false, fmt.Errorf("%s requires a value", a)
				}
				if strings.HasSuffix(a, "o") {
					output = args[i+1]
				}
				i++
			}
		default:
			inputs = append(inputs, a)
		}
	}
	switch {
	case output == "":
		return "", "", false, fmt.Errorf("an output file is required")
	case len(inputs) > 1:
		return "", "", false, fmt.Errorf("at most one input file is allowed")
	case len(inputs) == 0:
		inputs = []string{"-"}
	}
	return inputs[0], output, armor, nil
}

func openKey(ctx context.Context, spec, uid string) (*pgp.Key, error) {
	s, created, err := signer.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	return pgp.New(s, created, uid)
}
