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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"
)

// makeSelfSigned builds a self-signed RSA-2048 leaf certificate for tests.
func makeSelfSigned(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com", "alt.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse created certificate: %v", err)
	}

	return cert, key
}

func TestMetaFromLeaf(t *testing.T) {
	cert, _ := makeSelfSigned(t)

	meta := metaFromLeaf(cert)

	if meta.Subject != "CN=leaf.example.com" {
		t.Errorf("Subject = %q, want CN=leaf.example.com", meta.Subject)
	}
	assertSANs(t, meta.SANs)

	if !meta.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", meta.NotAfter, cert.NotAfter)
	}
	if !meta.NotBefore.Equal(cert.NotBefore) {
		t.Errorf("NotBefore = %v, want %v", meta.NotBefore, cert.NotBefore)
	}

	wantFP := hex.EncodeToString(sum256(cert.Raw))
	if meta.FingerprintSHA256 != wantFP {
		t.Errorf("FingerprintSHA256 = %q, want %q", meta.FingerprintSHA256, wantFP)
	}

	if meta.KeyAlgorithm != "RSA" {
		t.Errorf("KeyAlgorithm = %q, want RSA", meta.KeyAlgorithm)
	}
	if meta.KeyBits != 2048 {
		t.Errorf("KeyBits = %d, want 2048", meta.KeyBits)
	}
	if meta.SerialNumber != "12345" {
		t.Errorf("SerialNumber = %q, want 12345", meta.SerialNumber)
	}
	if meta.IsCA {
		t.Errorf("IsCA = true, want false for a non-CA leaf")
	}
}

// assertSANs verifies that the leaf's SANs are exactly its two DNS names
// plus its one IP address (and nothing else -- no email/URI entries).
func assertSANs(t *testing.T, sans []string) {
	t.Helper()
	if len(sans) != 3 {
		t.Fatalf("SANs = %v, want 3 entries (2 DNS + 1 IP)", sans)
	}
	foundDNS, foundIP := 0, 0
	for _, s := range sans {
		switch s {
		case "leaf.example.com", "alt.example.com":
			foundDNS++
		case "127.0.0.1":
			foundIP++
		}
	}
	if foundDNS != 2 || foundIP != 1 {
		t.Errorf("SANs = %v, want 2 DNS names + 127.0.0.1", sans)
	}
}

func sum256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
