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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

// testBundle returns a fully populated Bundle (leaf + key + 1 intermediate)
// built through Parse, so Export tests exercise the same normalized shape
// certsvc callers would see.
func testBundle(t *testing.T) Bundle {
	t.Helper()
	tc := makeTestChain(t)
	b, err := Parse(makePEMBundle(t, tc), "")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return b
}

func TestExportPEMBundle(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, PEMBundle, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	got, err := Parse(out, "")
	if err != nil {
		t.Fatalf("re-Parse() error = %v", err)
	}
	if !bytes.Equal(got.LeafPEM, b.LeafPEM) {
		t.Error("re-parsed LeafPEM does not match original")
	}
	if len(got.KeyPEM) == 0 {
		t.Error("re-parsed KeyPEM is empty")
	}
	if len(got.ChainPEM) != len(b.ChainPEM) {
		t.Errorf("re-parsed ChainPEM len = %d, want %d", len(got.ChainPEM), len(b.ChainPEM))
	}
}

func TestExportPEMCertOnly(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, PEMCertOnly, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	block, rest := pem.Decode(out)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Export(PEMCertOnly) did not produce a single CERTIFICATE block")
	}
	if next, _ := pem.Decode(rest); next != nil {
		t.Error("Export(PEMCertOnly) produced more than one PEM block")
	}
}

func TestExportPEMKeyOnlyEncrypted(t *testing.T) {
	b := testBundle(t)

	plain, err := Export(b, PEMKeyOnly, "")
	if err != nil {
		t.Fatalf("Export(plaintext) error = %v", err)
	}

	enc, err := Export(b, PEMKeyOnly, "strong-pass")
	if err != nil {
		t.Fatalf("Export(encrypted) error = %v", err)
	}

	// (a) encrypted output differs from plaintext output.
	if bytes.Equal(plain, enc) {
		t.Fatal("encrypted key output equals plaintext output")
	}
	block, _ := pem.Decode(enc)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("encrypted output is not an ENCRYPTED PRIVATE KEY block: %v", block)
	}

	// (b) round-trips back through Parse with the right passphrase to the
	// same key.
	got, err := Parse(enc, "strong-pass")
	if err != nil {
		t.Fatalf("Parse(encrypted, right pass) error = %v", err)
	}
	if !bytes.Equal(got.KeyPEM, b.KeyPEM) {
		t.Error("round-tripped key does not match the original plaintext key")
	}

	// (c) wrong passphrase fails with ErrWrongPassphrase.
	if _, err := Parse(enc, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Parse(encrypted, wrong pass) error = %v, want ErrWrongPassphrase", err)
	}
}

func TestExportPEMBundleEncrypted(t *testing.T) {
	b := testBundle(t)

	enc, err := Export(b, PEMBundle, "strong-pass")
	if err != nil {
		t.Fatalf("Export(encrypted bundle) error = %v", err)
	}

	// The bundle's key portion must be an encrypted block.
	var sawEncryptedKey bool
	rest := enc
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			sawEncryptedKey = true
		}
		if block.Type == "PRIVATE KEY" {
			t.Error("bundle contains a plaintext PRIVATE KEY block despite a passphrase")
		}
	}
	if !sawEncryptedKey {
		t.Fatal("encrypted bundle has no ENCRYPTED PRIVATE KEY block")
	}

	// Round-trips: leaf, chain and key all recovered with the right pass.
	got, err := Parse(enc, "strong-pass")
	if err != nil {
		t.Fatalf("Parse(encrypted bundle, right pass) error = %v", err)
	}
	if !bytes.Equal(got.LeafPEM, b.LeafPEM) {
		t.Error("re-parsed LeafPEM does not match original")
	}
	if !bytes.Equal(got.KeyPEM, b.KeyPEM) {
		t.Error("re-parsed KeyPEM does not match original")
	}
	if len(got.ChainPEM) != len(b.ChainPEM) {
		t.Errorf("re-parsed ChainPEM len = %d, want %d", len(got.ChainPEM), len(b.ChainPEM))
	}

	if _, err := Parse(enc, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Parse(encrypted bundle, wrong pass) error = %v, want ErrWrongPassphrase", err)
	}
}

func TestExportPEMKeyOnly(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, PEMKeyOnly, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	block, rest := pem.Decode(out)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("Export(PEMKeyOnly) did not produce a single PRIVATE KEY block")
	}
	if next, _ := pem.Decode(rest); next != nil {
		t.Error("Export(PEMKeyOnly) produced more than one PEM block")
	}
}

func TestExportPEMFullchain(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, PEMFullchain, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	var certCount int
	rest := out
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("Export(PEMFullchain) contained a non-certificate block: %s", block.Type)
		}
		certCount++
	}
	if certCount != 1+len(b.ChainPEM) {
		t.Errorf("Export(PEMFullchain) cert count = %d, want %d", certCount, 1+len(b.ChainPEM))
	}
}

func TestExportDER(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, DER, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if _, err := x509.ParseCertificate(out); err != nil {
		t.Fatalf("Export(DER) did not produce a parseable certificate: %v", err)
	}
}

func TestExportPKCS12(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, PKCS12, "export-pw")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	key, cert, caCerts, err := pkcs12.DecodeChain(out, "export-pw")
	if err != nil {
		t.Fatalf("DecodeChain() error = %v", err)
	}
	if key == nil {
		t.Error("decoded PKCS#12 has no private key")
	}
	if cert == nil {
		t.Error("decoded PKCS#12 has no leaf certificate")
	}
	if len(caCerts) != len(b.ChainPEM) {
		t.Errorf("decoded PKCS#12 chain len = %d, want %d", len(caCerts), len(b.ChainPEM))
	}
}

func TestExportPKCS7(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, PKCS7, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	p7, err := pkcs7.Parse(out)
	if err != nil {
		t.Fatalf("pkcs7.Parse() error = %v", err)
	}
	if len(p7.Certificates) != 1+len(b.ChainPEM) {
		t.Errorf("PKCS#7 cert count = %d, want %d", len(p7.Certificates), 1+len(b.ChainPEM))
	}
}

func TestExportJKS(t *testing.T) {
	b := testBundle(t)

	out, err := Export(b, JKS, "export-pw")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(out), []byte("export-pw")); err != nil {
		t.Fatalf("keystore.Load() error = %v", err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 1 {
		t.Fatalf("len(Aliases()) = %d, want 1", len(aliases))
	}
	entry, err := ks.GetPrivateKeyEntry(aliases[0], []byte("export-pw"))
	if err != nil {
		t.Fatalf("GetPrivateKeyEntry() error = %v", err)
	}
	if len(entry.CertificateChain) != 1+len(b.ChainPEM) {
		t.Errorf("JKS chain len = %d, want %d", len(entry.CertificateChain), 1+len(b.ChainPEM))
	}
}

func TestExportPKCS12NoPrivateKey(t *testing.T) {
	tc := makeTestChain(t)
	certOnly := Bundle{
		LeafPEM: certPEM(tc.LeafCert),
		Meta:    metaFromLeaf(tc.LeafCert),
	}

	_, err := Export(certOnly, PKCS12, "pw")
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Fatalf("Export() error = %v, want ErrNoPrivateKey", err)
	}
}
