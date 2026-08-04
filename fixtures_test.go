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

// Test fixture generators shared across *_test.go files. All fixtures are
// generated in-process (self-signed leaf + intermediate + key via
// crypto/x509) rather than committed as binary testdata.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testChain is a generated leaf + intermediate + their keys, useful as
// input to every format's parse/export round-trip test.
type testChain struct {
	LeafCert   *x509.Certificate
	LeafKey    *rsa.PrivateKey
	IntermCert *x509.Certificate
	IntermKey  *rsa.PrivateKey
}

// makeTestChain builds a self-signed intermediate CA and a leaf certificate
// issued by it, both RSA-2048.
func makeTestChain(t *testing.T) testChain {
	t.Helper()

	intermKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intermTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intermediate-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermDER, err := x509.CreateCertificate(rand.Reader, intermTmpl, intermTmpl, &intermKey.PublicKey, intermKey)
	if err != nil {
		t.Fatalf("create intermediate certificate: %v", err)
	}
	intermCert, err := x509.ParseCertificate(intermDER)
	if err != nil {
		t.Fatalf("parse intermediate certificate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermCert, &leafKey.PublicKey, intermKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return testChain{
		LeafCert:   leafCert,
		LeafKey:    leafKey,
		IntermCert: intermCert,
		IntermKey:  intermKey,
	}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func certPEM(c *x509.Certificate) []byte {
	return pemBlock("CERTIFICATE", c.Raw)
}

// keyPEM returns an unencrypted PKCS#8 PEM block for key.
func keyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	return pemBlock("PRIVATE KEY", der)
}

// encryptedKeyPEM returns a PBES2-encrypted "ENCRYPTED PRIVATE KEY" PEM
// block for key, protected by passphrase.
func encryptedKeyPEM(t *testing.T, key *rsa.PrivateKey, passphrase string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	encDER, err := encryptPKCS8(der, passphrase)
	if err != nil {
		t.Fatalf("encrypt PKCS#8 key: %v", err)
	}
	return pemBlock("ENCRYPTED PRIVATE KEY", encDER)
}

// makePEMBundle concatenates a leaf cert, its key and an intermediate cert
// into a single PEM stream (leaf+key+1 intermediate), as commonly produced
// by tools like certbot.
func makePEMBundle(t *testing.T, tc testChain) []byte {
	t.Helper()
	var out []byte
	out = append(out, certPEM(tc.LeafCert)...)
	out = append(out, keyPEM(t, tc.LeafKey)...)
	out = append(out, certPEM(tc.IntermCert)...)
	return out
}
