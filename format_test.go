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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func makeTestCertDER(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "detect-format-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func TestDetectFormatPEM(t *testing.T) {
	der := makeTestCertDER(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got := DetectFormat(pemBytes)
	switch got {
	case PEMCertOnly, PEMBundle, PEMFullchain, PEMKeyOnly:
		// any PEM variant is acceptable for this coarse check
	default:
		t.Fatalf("DetectFormat(pem cert) = %v, want a PEM format", got)
	}
}

func TestDetectFormatDER(t *testing.T) {
	der := makeTestCertDER(t)
	if got := DetectFormat(der); got != DER {
		t.Fatalf("DetectFormat(der) = %v, want DER", got)
	}
}

func TestDetectFormatPKCS12(t *testing.T) {
	// Minimal ASN.1 SEQUENCE that is not a parseable x509 certificate but
	// carries the pkcs-12 (1.2.840.113549.1.12) OID arcs, matching what a
	// real .p12/.pfx ContentInfo would contain. Not a real PKCS#12 file --
	// just enough for the best-effort sniff.
	pkcs12OID := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C}
	body := append([]byte{0x06, byte(len(pkcs12OID))}, pkcs12OID...)
	data := append([]byte{0x30, byte(len(body))}, body...)

	if got := DetectFormat(data); got != PKCS12 {
		t.Fatalf("DetectFormat(pkcs12-ish) = %v, want PKCS12", got)
	}

	// It must not be confused with a plain DER certificate.
	der := makeTestCertDER(t)
	if got := DetectFormat(der); got == PKCS12 {
		t.Fatalf("DetectFormat(der) misclassified as PKCS12")
	}
}

func TestDetectFormatPKCS7(t *testing.T) {
	pkcs7OID := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	body := append([]byte{0x06, byte(len(pkcs7OID))}, pkcs7OID...)
	data := append([]byte{0x30, byte(len(body))}, body...)

	if got := DetectFormat(data); got != PKCS7 {
		t.Fatalf("DetectFormat(pkcs7-ish) = %v, want PKCS7", got)
	}
}

func TestDetectFormatJKS(t *testing.T) {
	jks := []byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2}
	if got := DetectFormat(jks); got != JKS {
		t.Fatalf("DetectFormat(jks magic) = %v, want JKS", got)
	}

	jceks := []byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2}
	if got := DetectFormat(jceks); got != JKS {
		t.Fatalf("DetectFormat(jceks magic) = %v, want JKS", got)
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	if got := DetectFormat([]byte("not a certificate at all")); got != Unknown {
		t.Fatalf("DetectFormat(garbage) = %v, want Unknown", got)
	}
}
