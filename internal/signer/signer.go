package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func Open(ctx context.Context, spec string) (crypto.Signer, time.Time, error) {
	switch {
	case strings.HasPrefix(spec, "awskms:"):
		return openKMS(ctx, strings.TrimPrefix(spec, "awskms:"))
	case strings.HasPrefix(spec, "file:"):
		return openFile(strings.TrimPrefix(spec, "file:"))
	default:
		return nil, time.Time{}, fmt.Errorf("unsupported key %q: use awskms:<key-arn> or file:<path>", spec)
	}
}

var kmsAlgorithms = map[string]map[crypto.Hash]types.SigningAlgorithmSpec{
	"rsa": {
		crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	},
	"ecdsa": {
		crypto.SHA256: types.SigningAlgorithmSpecEcdsaSha256,
		crypto.SHA384: types.SigningAlgorithmSpecEcdsaSha384,
		crypto.SHA512: types.SigningAlgorithmSpecEcdsaSha512,
	},
}

type kmsSigner struct {
	ctx        context.Context
	client     *kms.Client
	keyID      string
	pub        crypto.PublicKey
	algorithms map[crypto.Hash]types.SigningAlgorithmSpec
}

func openKMS(ctx context.Context, keyID string) (crypto.Signer, time.Time, error) {
	var opts []func(*config.LoadOptions) error
	if arn := strings.Split(keyID, ":"); len(arn) >= 6 && arn[0] == "arn" && arn[2] == "kms" {
		opts = append(opts, config.WithRegion(arn[3]))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, time.Time{}, err
	}
	client := kms.NewFromConfig(cfg)

	desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("describing KMS key: %w", err)
	}
	md := desc.KeyMetadata
	switch {
	case md.KeyState != types.KeyStateEnabled:
		return nil, time.Time{}, fmt.Errorf("KMS key is %s", md.KeyState)
	case md.KeyUsage != types.KeyUsageTypeSignVerify:
		return nil, time.Time{}, fmt.Errorf("KMS key usage is %s, SIGN_VERIFY is required", md.KeyUsage)
	case md.CreationDate == nil:
		return nil, time.Time{}, fmt.Errorf("KMS key has no creation date")
	}

	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("getting KMS public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	s := &kmsSigner{ctx: ctx, client: client, keyID: keyID, pub: pub}
	switch pub.(type) {
	case *rsa.PublicKey:
		s.algorithms = kmsAlgorithms["rsa"]
	case *ecdsa.PublicKey:
		s.algorithms = kmsAlgorithms["ecdsa"]
	default:
		return nil, time.Time{}, fmt.Errorf("unsupported KMS key spec %s", md.KeySpec)
	}
	return s, *md.CreationDate, nil
}

func (s *kmsSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("RSA-PSS is not supported")
	}
	algorithm, ok := s.algorithms[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash %v", opts.HashFunc())
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: algorithm,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil
}

func openFile(path string) (crypto.Signer, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, time.Time{}, fmt.Errorf("%s: no PEM block found", path)
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, time.Time{}, fmt.Errorf("%s: unsupported private key type %T", path, key)
	}
	return signer, st.ModTime(), nil
}
