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
	"encoding/pem"
	"errors"
	"testing"
)

func TestParsePEMBundle(t *testing.T) {
	tc := makeTestChain(t)
	bundlePEM := makePEMBundle(t, tc)

	b, err := Parse(bundlePEM, "")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	block, _ := pem.Decode(b.LeafPEM)
	if block == nil {
		t.Fatal("LeafPEM did not decode as PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("LeafPEM did not parse as a certificate: %v", err)
	}
	if leaf.Subject.CommonName != "leaf.example.com" {
		t.Errorf("leaf CN = %q, want leaf.example.com", leaf.Subject.CommonName)
	}

	if len(b.KeyPEM) == 0 {
		t.Error("KeyPEM is empty, want the leaf's private key")
	}
	if len(b.ChainPEM) != 1 {
		t.Fatalf("len(ChainPEM) = %d, want 1", len(b.ChainPEM))
	}
	if b.Meta.Subject == "" {
		t.Error("Meta.Subject is empty, want it set")
	}
}

func TestParseDERCertOnly(t *testing.T) {
	tc := makeTestChain(t)

	b, err := Parse(tc.LeafCert.Raw, "")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	block, _ := pem.Decode(b.LeafPEM)
	if block == nil {
		t.Fatal("LeafPEM did not decode as PEM")
	}
	if len(b.KeyPEM) != 0 {
		t.Errorf("KeyPEM = %q, want empty for a bare DER cert", b.KeyPEM)
	}
	if len(b.ChainPEM) != 0 {
		t.Errorf("len(ChainPEM) = %d, want 0", len(b.ChainPEM))
	}
	if b.Meta.Subject == "" {
		t.Error("Meta.Subject is empty, want it set")
	}
}

func TestParseEncryptedPEMKeyWrongPassphrase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tc := makeTestChain(t)
	var data []byte
	data = append(data, certPEM(tc.LeafCert)...)
	data = append(data, encryptedKeyPEM(t, key, "correct-horse")...)

	_, err = Parse(data, "wrong-passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Parse() error = %v, want ErrWrongPassphrase", err)
	}
}

func TestParseEncryptedPEMKeyRightPassphrase(t *testing.T) {
	tc := makeTestChain(t)
	var data []byte
	data = append(data, certPEM(tc.LeafCert)...)
	data = append(data, encryptedKeyPEM(t, tc.LeafKey, "correct-horse")...)

	b, err := Parse(data, "correct-horse")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(b.KeyPEM) == 0 {
		t.Error("KeyPEM is empty, want the decrypted key")
	}
}
