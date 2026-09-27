package pgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

func testKeys(t *testing.T) map[string]*Key {
	t.Helper()
	keys := map[string]*Key{}
	signers := map[string]func() (crypto.Signer, error){
		"rsa":  func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) },
		"p256": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
		"p384": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
	}
	for name, gen := range signers {
		s, err := gen()
		if err != nil {
			t.Fatal(err)
		}
		k, err := New(s, time.Now().Add(-time.Hour), "Test Packages <test@example.com>")
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = k
	}
	return keys
}

func TestDeterministicPublicKey(t *testing.T) {
	k := testKeys(t)["rsa"]
	a, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("public key export is not deterministic")
	}
}

func TestSignaturesVerify(t *testing.T) {
	for name, k := range testKeys(t) {
		t.Run(name, func(t *testing.T) { testSignaturesVerify(t, k) })
	}
}

func testSignaturesVerify(t *testing.T, k *Key) {
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := openpgp.ReadKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatal(err)
	}
	if len(ring) != 1 {
		t.Fatalf("expected one entity, got %d", len(ring))
	}
	if got := strings.ToUpper(ring[0].PrimaryKey.KeyIdString()); !strings.HasSuffix(k.Fingerprint(), got) {
		t.Fatalf("fingerprint mismatch: %s vs %s", got, k.Fingerprint())
	}
	armored, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(Armor("PGP PUBLIC KEY BLOCK", pub)))
	if err != nil || len(armored) != 1 {
		t.Fatalf("armored key: %v", err)
	}

	data := []byte("Origin: Test\nLabel: Test\n")
	sig, err := k.Sign(bytes.NewReader(data), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, bytes.NewReader(data), bytes.NewReader(sig), nil); err != nil {
		t.Fatalf("detached: %v", err)
	}
	asig, err := k.ArmoredSign(bytes.NewReader(data), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(ring, bytes.NewReader(data), bytes.NewReader(asig), nil); err != nil {
		t.Fatalf("armored detached: %v", err)
	}

	text := []byte("Origin: Test\n-dash line\ntrailing  \nMD5Sum:\n abc 12 main/binary-amd64/Packages\n")
	clear, err := k.ClearSign(text, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, rest := clearsign.Decode(clear)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("cannot decode cleartext signature")
	}
	if _, err := block.VerifySignature(ring, nil); err != nil {
		t.Fatalf("cleartext: %v", err)
	}
	if want := "Origin: Test\n-dash line\ntrailing\nMD5Sum:\n abc 12 main/binary-amd64/Packages\n"; string(block.Plaintext)+"\n" != want && string(block.Plaintext) != want {
		t.Fatalf("unexpected plaintext %q", block.Plaintext)
	}
}

func TestGnuPG(t *testing.T) {
	gpgv, err := exec.LookPath("gpgv")
	if err != nil {
		t.Skip("gpgv is not installed")
	}
	for name, k := range testKeys(t) {
		t.Run(name, func(t *testing.T) { testGnuPG(t, gpgv, k) })
	}
}

func testGnuPG(t *testing.T, gpgv string, k *Key) {
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyring := filepath.Join(dir, "keyring.gpg")
	data := []byte("Suite: stable\n")
	sig, err := k.ArmoredSign(bytes.NewReader(data), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clear, err := k.ClearSign(data, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"keyring.gpg": pub, "Release": data, "Release.gpg": sig, "InRelease": clear} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"--keyring", keyring, filepath.Join(dir, "Release.gpg"), filepath.Join(dir, "Release")},
		{"--keyring", keyring, filepath.Join(dir, "InRelease")},
	} {
		cmd := exec.Command(gpgv, args...)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gpgv %v: %v\n%s", args, err, out)
		}
	}
}

func TestRejectsSmallKeys(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(priv, time.Now(), "x"); err == nil {
		t.Fatal("expected error for 1024-bit key")
	}
}
