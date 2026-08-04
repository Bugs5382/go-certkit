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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func makeTestP12(t *testing.T, tc testChain, passphrase string) []byte {
	t.Helper()
	data, err := pkcs12.Modern.Encode(tc.LeafKey, tc.LeafCert, []*x509.Certificate{tc.IntermCert}, passphrase)
	if err != nil {
		t.Fatalf("encode PKCS#12: %v", err)
	}
	return data
}

func TestParsePKCS12(t *testing.T) {
	tc := makeTestChain(t)
	p12 := makeTestP12(t, tc, "changeit")

	b, err := Parse(p12, "changeit")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	block, _ := pem.Decode(b.LeafPEM)
	if block == nil {
		t.Fatal("LeafPEM did not decode as PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("LeafPEM did not parse: %v", err)
	}
	if leaf.Subject.CommonName != "leaf.example.com" {
		t.Errorf("leaf CN = %q, want leaf.example.com", leaf.Subject.CommonName)
	}

	if len(b.KeyPEM) == 0 {
		t.Error("KeyPEM is empty, want the leaf's private key")
	}
	if _, err := x509.ParsePKCS8PrivateKey(mustPEMBytes(t, b.KeyPEM)); err != nil {
		t.Errorf("KeyPEM did not parse as PKCS#8: %v", err)
	}
	if len(b.ChainPEM) != 1 {
		t.Fatalf("len(ChainPEM) = %d, want 1", len(b.ChainPEM))
	}
	if b.Meta.Subject == "" {
		t.Error("Meta.Subject is empty, want it set")
	}
}

func TestParsePKCS12WrongPassphrase(t *testing.T) {
	tc := makeTestChain(t)
	p12 := makeTestP12(t, tc, "changeit")

	_, err := Parse(p12, "wrong-passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Parse() error = %v, want ErrWrongPassphrase", err)
	}
}

func mustPEMBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected PEM data")
	}
	return block.Bytes
}
