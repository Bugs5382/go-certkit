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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// defaultKeyBits is the RSA modulus size used when GenOpts.KeyBits is zero.
const defaultKeyBits = 2048

// defaultTTL is the certificate lifetime used when GenOpts.TTL is zero.
const defaultTTL = 365 * 24 * time.Hour

// serialNumberLimit bounds the random serial numbers generated for
// self-signed certificates: an unsigned 128-bit value, matching common CA
// practice.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// GenOpts configures GenerateSelfSigned and Rotate.
type GenOpts struct {
	// CommonName is the certificate Subject's common name. Required.
	CommonName string
	// DNSNames populates the certificate's Subject Alternative Names.
	DNSNames []string
	// TTL is the certificate lifetime, measured from the time of
	// generation. A zero value defaults to 365 days.
	TTL time.Duration
	// KeyBits is the RSA modulus size in bits. A zero value defaults to
	// 2048.
	KeyBits int
}

// GenerateSelfSigned creates a fresh RSA keypair and a self-signed leaf
// certificate for it, returning both as a Bundle. The returned Bundle has no
// ChainPEM, since a self-signed leaf is its own trust anchor.
//
// The certificate is suited to a TLS/signing service leaf: it carries
// DigitalSignature and KeyEncipherment key usage, ExtKeyUsageServerAuth and
// ExtKeyUsageClientAuth extended usages, and is not a CA.
func GenerateSelfSigned(opts GenOpts) (Bundle, error) {
	if opts.CommonName == "" {
		return Bundle{}, fmt.Errorf("certkit: GenOpts.CommonName is required")
	}

	keyBits := opts.KeyBits
	if keyBits == 0 {
		keyBits = defaultKeyBits
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return Bundle{}, fmt.Errorf("certkit: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return Bundle{}, fmt.Errorf("certkit: generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: opts.CommonName},
		DNSNames:     opts.DNSNames,
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return Bundle{}, fmt.Errorf("certkit: create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return Bundle{}, fmt.Errorf("certkit: parse generated certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, fmt.Errorf("certkit: marshal private key: %w", err)
	}

	return Bundle{
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Meta:    metaFromLeaf(cert),
	}, nil
}

// Rotate generates a fresh keypair and self-signed certificate, returning it
// as a brand-new Bundle for graceful-overlap rotation: callers keep serving
// current while next is distributed, then cut over. Rotate never mutates
// current and never reuses its private key.
//
// If opts is the zero value, CommonName and DNSNames are derived from
// current's metadata so a caller can rotate without restating them.
func Rotate(current Bundle, opts GenOpts) (Bundle, error) {
	if opts.CommonName == "" {
		opts.CommonName = commonNameFromSubject(current.Meta.Subject)
	}
	if len(opts.DNSNames) == 0 {
		opts.DNSNames = current.Meta.SANs
	}
	return GenerateSelfSigned(opts)
}

// commonNameFromSubject extracts the CN attribute from an RDN subject string
// produced by pkix.Name.String() (e.g. "CN=sp.example.com" or
// "CN=sp.example.com,O=Example Co"). It returns "" if no CN attribute is
// present. This is a best-effort split on unescaped commas; it is exact for
// subjects generated by GenerateSelfSigned, which only ever sets CommonName.
func commonNameFromSubject(subject string) string {
	for _, rdn := range strings.Split(subject, ",") {
		if cn, ok := strings.CutPrefix(rdn, "CN="); ok {
			return cn
		}
	}
	return ""
}
