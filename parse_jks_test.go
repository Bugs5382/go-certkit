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
	"errors"
	"sort"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func makeTestJKS(t *testing.T, tc testChain, storePassphrase string) []byte {
	t.Helper()

	keyDER, err := x509.MarshalPKCS8PrivateKey(tc.LeafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}

	ks := keystore.New()

	pke := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   keyDER,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: tc.LeafCert.Raw},
			{Type: "X509", Content: tc.IntermCert.Raw},
		},
	}
	if err := ks.SetPrivateKeyEntry("a1", pke, []byte(storePassphrase)); err != nil {
		t.Fatalf("SetPrivateKeyEntry: %v", err)
	}

	tce := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X509", Content: tc.IntermCert.Raw},
	}
	if err := ks.SetTrustedCertificateEntry("a2", tce); err != nil {
		t.Fatalf("SetTrustedCertificateEntry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(storePassphrase)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	return buf.Bytes()
}

func TestParseJKSMultipleAliases(t *testing.T) {
	tc := makeTestChain(t)
	jks := makeTestJKS(t, tc, "changeit")

	_, err := Parse(jks, "changeit")

	var multi *ErrMultipleEntries
	if !errors.As(err, &multi) {
		t.Fatalf("Parse() error = %v, want *ErrMultipleEntries", err)
	}
	got := append([]string(nil), multi.Aliases...)
	sort.Strings(got)
	want := []string{"a1", "a2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Aliases = %v, want %v", multi.Aliases, want)
	}
}

func TestParseEntryJKS(t *testing.T) {
	tc := makeTestChain(t)
	jks := makeTestJKS(t, tc, "changeit")

	b, err := ParseEntry(jks, "changeit", "a1")
	if err != nil {
		t.Fatalf("ParseEntry() error = %v", err)
	}
	if len(b.KeyPEM) == 0 {
		t.Error("KeyPEM is empty, want the private key entry's key")
	}
	if len(b.ChainPEM) != 1 {
		t.Fatalf("len(ChainPEM) = %d, want 1", len(b.ChainPEM))
	}
	if b.Meta.Subject == "" {
		t.Error("Meta.Subject is empty, want it set")
	}
}

func TestParseEntryJKSTrustedCertOnly(t *testing.T) {
	tc := makeTestChain(t)
	jks := makeTestJKS(t, tc, "changeit")

	b, err := ParseEntry(jks, "changeit", "a2")
	if err != nil {
		t.Fatalf("ParseEntry() error = %v", err)
	}
	if len(b.KeyPEM) != 0 {
		t.Errorf("KeyPEM = %q, want empty for a trusted-cert-only entry", b.KeyPEM)
	}
	if b.Meta.Subject == "" {
		t.Error("Meta.Subject is empty, want it set")
	}
}

func TestParseJKSWrongPassphrase(t *testing.T) {
	tc := makeTestChain(t)
	jks := makeTestJKS(t, tc, "changeit")

	_, err := Parse(jks, "wrong-passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Parse() error = %v, want ErrWrongPassphrase", err)
	}
}

func TestParseJKSMagicButCorrupt(t *testing.T) {
	// JKS magic (0xFEEDFEED) followed by a valid version but a truncated
	// entry count -- a corrupt/foreign file, not a wrong passphrase. It must
	// not be reported as ErrWrongPassphrase.
	corrupt := []byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 1, 2, 3}

	_, err := Parse(corrupt, "changeit")
	if !errors.Is(err, ErrUnrecognizedFormat) {
		t.Fatalf("Parse(corrupt jks) error = %v, want ErrUnrecognizedFormat", err)
	}
	if errors.Is(err, ErrWrongPassphrase) {
		t.Fatal("Parse(corrupt jks) misreported as ErrWrongPassphrase")
	}
}
