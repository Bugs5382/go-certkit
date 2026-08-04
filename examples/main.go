// Command example demonstrates parsing a PEM certificate bundle into a
// certkit.Bundle, printing its metadata, and converting it to another
// container format. It generates its own self-signed material so it runs
// standalone: `go run ./examples`.
package main

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
	"log"
	"math/big"
	"time"

	"github.com/Bugs5382/go-certkit"
)

func main() {
	pemBytes := generateSelfSignedPEM()

	// Parse any supported container (here a PEM leaf + key) into one
	// normalized Bundle.
	bundle, err := certkit.Parse(pemBytes, "")
	if err != nil {
		log.Fatalf("parse: %v", err)
	}

	fmt.Println("Subject:    ", bundle.Meta.Subject)
	fmt.Println("SANs:       ", bundle.Meta.SANs)
	fmt.Println("Not after:  ", bundle.Meta.NotAfter.Format(time.RFC3339))
	fmt.Printf("Key:         %s %d-bit\n", bundle.Meta.KeyAlgorithm, bundle.Meta.KeyBits)
	fmt.Println("SHA-256:    ", bundle.Meta.FingerprintSHA256)

	// Convert the same material to a password-protected PKCS#12 archive.
	p12, err := certkit.Export(bundle, certkit.PKCS12, "changeit")
	if err != nil {
		log.Fatalf("export: %v", err)
	}
	fmt.Printf("Converted to a %d-byte PKCS#12 archive\n", len(p12))
}

// generateSelfSignedPEM builds a throwaway self-signed leaf + key and returns
// them concatenated as a PEM bundle.
func generateSelfSignedPEM() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}

	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return out
}
