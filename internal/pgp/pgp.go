package pgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

const (
	tagSignature = 2
	tagPublicKey = 6
	tagUserID    = 13

	sigBinary        = 0x00
	sigText          = 0x01
	sigPositiveCert  = 0x13
	algoRSA          = 1
	algoECDSA        = 19
	hashSHA256       = 8
	hashSHA384       = 9
	hashSHA512       = 10
	subCreationTime  = 2
	subIssuer        = 16
	subPreferredHash = 21
	subKeyFlags      = 27
	subIssuerFpr     = 33
	keyFlagsCertSign = 0x03
	minRSABits       = 2048
)

var (
	curves = map[string]struct {
		oid  []byte
		hash crypto.Hash
	}{
		"P-256": {[]byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, crypto.SHA256},
		"P-384": {[]byte{0x2b, 0x81, 0x04, 0x00, 0x22}, crypto.SHA384},
		"P-521": {[]byte{0x2b, 0x81, 0x04, 0x00, 0x23}, crypto.SHA512},
	}
	hashIDs   = map[crypto.Hash]byte{crypto.SHA256: hashSHA256, crypto.SHA384: hashSHA384, crypto.SHA512: hashSHA512}
	hashNames = map[crypto.Hash]string{crypto.SHA256: "SHA256", crypto.SHA384: "SHA384", crypto.SHA512: "SHA512"}
)

type Key struct {
	signer  crypto.Signer
	pub     crypto.PublicKey
	algo    byte
	hash    crypto.Hash
	created time.Time
	uid     string
	body    []byte
	fpr     []byte
}

func New(signer crypto.Signer, created time.Time, uid string) (*Key, error) {
	k := &Key{signer: signer, pub: signer.Public(), created: created.UTC().Truncate(time.Second), uid: uid}
	var material []byte
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key is %d bits, at least %d are required", pub.N.BitLen(), minRSABits)
		}
		k.algo, k.hash = algoRSA, crypto.SHA256
		material = concat(mpi(pub.N.Bytes()), mpi(big.NewInt(int64(pub.E)).Bytes()))
	case *ecdsa.PublicKey:
		curve, ok := curves[pub.Curve.Params().Name]
		if !ok {
			return nil, fmt.Errorf("unsupported ECDSA curve %s", pub.Curve.Params().Name)
		}
		point, err := pub.ECDH()
		if err != nil {
			return nil, err
		}
		k.algo, k.hash = algoECDSA, curve.hash
		material = concat([]byte{byte(len(curve.oid))}, curve.oid, mpi(point.Bytes()))
	default:
		return nil, fmt.Errorf("unsupported signing key type %T: an RSA or ECDSA key is required", k.pub)
	}

	k.body = concat([]byte{4}, unix(k.created), []byte{k.algo}, material)
	h := sha1.New()
	h.Write(keyPrefix(k.body))
	h.Write(k.body)
	k.fpr = h.Sum(nil)
	return k, nil
}

func (k *Key) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(k.fpr))
}

func (k *Key) Created() time.Time {
	return k.created
}

func (k *Key) PublicKey() ([]byte, error) {
	if k.uid == "" {
		return nil, fmt.Errorf("user ID is required")
	}
	hashed := concat(
		subpacket(subCreationTime, unix(k.created)),
		subpacket(subKeyFlags, []byte{keyFlagsCertSign}),
		subpacket(subPreferredHash, []byte{hashSHA256, hashSHA512, hashSHA384}),
		subpacket(subIssuerFpr, append([]byte{4}, k.fpr...)),
	)
	uid := []byte(k.uid)
	prefix := keyPrefix(k.body)
	prefix = append(prefix, k.body...)
	prefix = append(prefix, 0xb4)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(uid)))
	prefix = append(prefix, uid...)

	sig, err := k.signature(sigPositiveCert, hashed, bytes.NewReader(prefix))
	if err != nil {
		return nil, err
	}
	return concat(packet(tagPublicKey, k.body), packet(tagUserID, uid), sig), nil
}

func (k *Key) Sign(r io.Reader, t time.Time) ([]byte, error) {
	return k.signature(sigBinary, k.dataSubpackets(t), r)
}

func (k *Key) ArmoredSign(r io.Reader, t time.Time) ([]byte, error) {
	sig, err := k.Sign(r, t)
	if err != nil {
		return nil, err
	}
	return Armor("PGP SIGNATURE", sig), nil
}

func (k *Key) ClearSign(text []byte, t time.Time) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t\r")
	}

	sig, err := k.signature(sigText, k.dataSubpackets(t), strings.NewReader(strings.Join(lines, "\r\n")))
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\nHash: " + hashNames[k.hash] + "\n\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "-") {
			b.WriteString("- ")
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.Write(Armor("PGP SIGNATURE", sig))
	return b.Bytes(), nil
}

func (k *Key) dataSubpackets(t time.Time) []byte {
	if t.Before(k.created) {
		t = k.created
	}
	return concat(
		subpacket(subCreationTime, unix(t)),
		subpacket(subIssuerFpr, append([]byte{4}, k.fpr...)),
	)
}

func (k *Key) signature(sigType byte, hashed []byte, data io.Reader) ([]byte, error) {
	if len(hashed) > 0xffff {
		return nil, fmt.Errorf("hashed subpackets too long")
	}
	head := []byte{4, sigType, k.algo, hashIDs[k.hash]}
	head = binary.BigEndian.AppendUint16(head, uint16(len(hashed)))
	head = append(head, hashed...)

	h := k.hash.New()
	if _, err := io.Copy(h, data); err != nil {
		return nil, err
	}
	h.Write(head)
	h.Write([]byte{4, 0xff})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(head))))
	digest := h.Sum(nil)

	raw, err := k.signer.Sign(rand.Reader, digest, k.hash)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	var material []byte
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, k.hash, digest, raw); err != nil {
			return nil, fmt.Errorf("signer returned an invalid signature: %w", err)
		}
		material = mpi(raw)
	case *ecdsa.PublicKey:
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(raw, &rs); err != nil || len(rest) != 0 || !ecdsa.VerifyASN1(pub, digest, raw) {
			return nil, fmt.Errorf("signer returned an invalid signature")
		}
		material = concat(mpi(rs.R.Bytes()), mpi(rs.S.Bytes()))
	}

	unhashed := subpacket(subIssuer, k.fpr[12:])
	body := append([]byte{}, head...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[0], digest[1])
	body = append(body, material...)
	return packet(tagSignature, body), nil
}

func Armor(blockType string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString("-----BEGIN " + blockType + "-----\n\n")
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 64 {
		b.WriteString(enc[:64])
		b.WriteByte('\n')
		enc = enc[64:]
	}
	if enc != "" {
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	crc := crc24(data)
	b.WriteString("=" + base64.StdEncoding.EncodeToString([]byte{byte(crc >> 16), byte(crc >> 8), byte(crc)}) + "\n")
	b.WriteString("-----END " + blockType + "-----\n")
	return b.Bytes()
}

func crc24(data []byte) uint32 {
	crc := uint32(0xb704ce)
	for _, c := range data {
		crc ^= uint32(c) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864cfb
			}
		}
	}
	return crc & 0xffffff
}

func keyPrefix(body []byte) []byte {
	return binary.BigEndian.AppendUint16([]byte{0x99}, uint16(len(body)))
}

func packet(tag byte, body []byte) []byte {
	n := len(body)
	switch {
	case n < 1<<8:
		return concat([]byte{0x80 | tag<<2, byte(n)}, body)
	case n < 1<<16:
		return concat([]byte{0x80 | tag<<2 | 1, byte(n >> 8), byte(n)}, body)
	default:
		return concat(binary.BigEndian.AppendUint32([]byte{0x80 | tag<<2 | 2}, uint32(n)), body)
	}
}

func subpacket(typ byte, data []byte) []byte {
	n := len(data) + 1
	var l []byte
	switch {
	case n < 192:
		l = []byte{byte(n)}
	case n < 8384:
		n -= 192
		l = []byte{byte(n>>8) + 192, byte(n)}
	default:
		l = binary.BigEndian.AppendUint32([]byte{0xff}, uint32(n))
	}
	return concat(l, []byte{typ}, data)
}

func mpi(b []byte) []byte {
	b = bytes.TrimLeft(b, "\x00")
	bits := 0
	if len(b) > 0 {
		bits = (len(b)-1)*8 + new(big.Int).SetBytes(b[:1]).BitLen()
	}
	return concat(binary.BigEndian.AppendUint16(nil, uint16(bits)), b)
}

func unix(t time.Time) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(t.Unix()))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
