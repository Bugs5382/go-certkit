package certkit

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"
)

// Bundle is the normalized, in-memory representation of a parsed
// certificate/key container: a leaf certificate, its optional private key,
// an optional chain of intermediate/root certificates, and derived metadata.
// LeafPEM, KeyPEM and each entry of ChainPEM are PEM-encoded blocks.
type Bundle struct {
	LeafPEM  []byte
	KeyPEM   []byte
	ChainPEM [][]byte
	Meta     Meta
}

// Meta holds certificate metadata derived from a Bundle's leaf certificate.
type Meta struct {
	Subject           string
	Issuer            string
	SANs              []string
	NotBefore         time.Time
	NotAfter          time.Time
	SerialNumber      string
	FingerprintSHA256 string
	KeyAlgorithm      string
	KeyBits           int
	IsCA              bool
}

// metaFromLeaf derives Meta from a parsed leaf certificate.
func metaFromLeaf(c *x509.Certificate) Meta {
	sans := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs))
	sans = append(sans, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, c.EmailAddresses...)
	for _, u := range c.URIs {
		sans = append(sans, u.String())
	}

	fingerprint := sha256.Sum256(c.Raw)

	keyAlg, keyBits := keyAlgorithmAndBits(c.PublicKey)

	return Meta{
		Subject:           c.Subject.String(),
		Issuer:            c.Issuer.String(),
		SANs:              sans,
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
		SerialNumber:      c.SerialNumber.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		KeyAlgorithm:      keyAlg,
		KeyBits:           keyBits,
		IsCA:              c.IsCA,
	}
}

// keyAlgorithmAndBits identifies the public key algorithm name and its
// effective bit size for the common key types.
func keyAlgorithmAndBits(pub any) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", len(k) * 8
	default:
		return "unknown", 0
	}
}
