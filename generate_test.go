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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestGenerateSelfSigned_Basic(t *testing.T) {
	opts := GenOpts{
		CommonName: "sp.example.com",
		DNSNames:   []string{"sp.example.com"},
	}

	b, err := GenerateSelfSigned(opts)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	if len(b.LeafPEM) == 0 {
		t.Fatal("LeafPEM is empty")
	}
	if len(b.KeyPEM) == 0 {
		t.Fatal("KeyPEM is empty")
	}
	if len(b.ChainPEM) != 0 {
		t.Fatalf("ChainPEM = %d entries, want 0 for a self-signed leaf", len(b.ChainPEM))
	}

	if b.Meta.Subject != "CN=sp.example.com" {
		t.Fatalf("Meta.Subject = %q, want %q", b.Meta.Subject, "CN=sp.example.com")
	}
	if !b.Meta.NotAfter.After(time.Now()) {
		t.Fatalf("Meta.NotAfter = %v, want a time after now", b.Meta.NotAfter)
	}
	if len(b.Meta.SANs) != 1 || b.Meta.SANs[0] != "sp.example.com" {
		t.Fatalf("Meta.SANs = %v, want [sp.example.com]", b.Meta.SANs)
	}
	if b.Meta.IsCA {
		t.Fatal("Meta.IsCA = true, want a leaf (non-CA) certificate")
	}
}

func TestGenerateSelfSigned_ExportRoundTrip(t *testing.T) {
	b, err := GenerateSelfSigned(GenOpts{
		CommonName: "sp.example.com",
		DNSNames:   []string{"sp.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	certOut, err := Export(b, PEMCertOnly, "")
	if err != nil {
		t.Fatalf("Export(PEMCertOnly): %v", err)
	}
	block, _ := pem.Decode(certOut)
	if block == nil {
		t.Fatal("Export(PEMCertOnly) did not produce a PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("re-parse exported certificate: %v", err)
	}

	keyOut, err := Export(b, PEMKeyOnly, "")
	if err != nil {
		t.Fatalf("Export(PEMKeyOnly): %v", err)
	}
	keyBlock, _ := pem.Decode(keyOut)
	if keyBlock == nil {
		t.Fatal("Export(PEMKeyOnly) did not produce a PEM block")
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("re-parse exported private key: %v", err)
	}
}

func TestGenerateSelfSigned_EmptyCommonName(t *testing.T) {
	_, err := GenerateSelfSigned(GenOpts{})
	if err == nil {
		t.Fatal("GenerateSelfSigned with an empty CommonName: want an error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "certkit:") {
		t.Fatalf("error = %q, want a certkit-prefixed error", err.Error())
	}
}

func TestGenerateSelfSigned_DefaultKeyBits(t *testing.T) {
	b, err := GenerateSelfSigned(GenOpts{CommonName: "sp.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if b.Meta.KeyAlgorithm != "RSA" {
		t.Fatalf("Meta.KeyAlgorithm = %q, want RSA", b.Meta.KeyAlgorithm)
	}
	if b.Meta.KeyBits != 2048 {
		t.Fatalf("Meta.KeyBits = %d, want 2048 default", b.Meta.KeyBits)
	}

	keyBlock, _ := pem.Decode(b.KeyPEM)
	if keyBlock == nil {
		t.Fatal("KeyPEM did not decode")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS#8 key: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *rsa.PrivateKey", key)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Fatalf("key size = %d bits, want 2048", rsaKey.N.BitLen())
	}
}

func TestGenerateSelfSigned_CustomKeyBitsAndTTL(t *testing.T) {
	ttl := 48 * time.Hour
	b, err := GenerateSelfSigned(GenOpts{
		CommonName: "sp.example.com",
		KeyBits:    3072,
		TTL:        ttl,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if b.Meta.KeyBits != 3072 {
		t.Fatalf("Meta.KeyBits = %d, want 3072", b.Meta.KeyBits)
	}

	wantNotAfter := time.Now().Add(ttl)
	if b.Meta.NotAfter.After(wantNotAfter.Add(time.Minute)) || b.Meta.NotAfter.Before(wantNotAfter.Add(-time.Minute)) {
		t.Fatalf("Meta.NotAfter = %v, want close to %v", b.Meta.NotAfter, wantNotAfter)
	}
}

func TestGenerateSelfSigned_DefaultTTL(t *testing.T) {
	b, err := GenerateSelfSigned(GenOpts{CommonName: "sp.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	wantMin := time.Now().Add(364 * 24 * time.Hour)
	wantMax := time.Now().Add(366 * 24 * time.Hour)
	if b.Meta.NotAfter.Before(wantMin) || b.Meta.NotAfter.After(wantMax) {
		t.Fatalf("Meta.NotAfter = %v, want ~365 days from now", b.Meta.NotAfter)
	}
}

func TestRotate(t *testing.T) {
	opts := GenOpts{
		CommonName: "sp.example.com",
		DNSNames:   []string{"sp.example.com"},
	}
	current, err := GenerateSelfSigned(opts)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	currentLeafPEM := append([]byte{}, current.LeafPEM...)
	currentKeyPEM := append([]byte{}, current.KeyPEM...)
	currentSerial := current.Meta.SerialNumber

	next, err := Rotate(current, opts)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if !bytes.Equal(current.LeafPEM, currentLeafPEM) {
		t.Fatal("Rotate mutated current.LeafPEM")
	}
	if !bytes.Equal(current.KeyPEM, currentKeyPEM) {
		t.Fatal("Rotate mutated current.KeyPEM")
	}
	if current.Meta.SerialNumber != currentSerial {
		t.Fatal("Rotate mutated current.Meta")
	}

	if bytes.Equal(next.KeyPEM, current.KeyPEM) {
		t.Fatal("Rotate reused the current private key; want a fresh keypair")
	}
	if next.Meta.SerialNumber == current.Meta.SerialNumber {
		t.Fatal("Rotate produced the same serial number as current")
	}
	if next.Meta.Subject != "CN=sp.example.com" {
		t.Fatalf("next.Meta.Subject = %q, want %q", next.Meta.Subject, "CN=sp.example.com")
	}
}

func TestRotate_DerivesFromCurrentWhenOptsZeroValue(t *testing.T) {
	current, err := GenerateSelfSigned(GenOpts{
		CommonName: "sp.example.com",
		DNSNames:   []string{"sp.example.com", "www.sp.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	next, err := Rotate(current, GenOpts{})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if next.Meta.Subject != current.Meta.Subject {
		t.Fatalf("next.Meta.Subject = %q, want %q (derived from current)", next.Meta.Subject, current.Meta.Subject)
	}
	if len(next.Meta.SANs) != len(current.Meta.SANs) {
		t.Fatalf("next.Meta.SANs = %v, want %v (derived from current)", next.Meta.SANs, current.Meta.SANs)
	}
}

func TestRotate_EmptyCommonNameNoCurrent(t *testing.T) {
	_, err := Rotate(Bundle{}, GenOpts{})
	if err == nil {
		t.Fatal("Rotate with no current bundle and no CommonName: want an error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "certkit:") {
		t.Fatalf("error = %q, want a certkit-prefixed error", err.Error())
	}
}
