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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

// Export assembles a Bundle into the given container Format, returning the
// encoded bytes. newPassphrase protects the output for formats that support
// encryption (PKCS#12, JKS); pass "" for the PEM/DER/PKCS#7 formats, which
// are never encrypted by Export.
//
// Exporting a key-bearing format (PKCS12, JKS, PEMBundle, PEMKeyOnly) from a
// Bundle with no private key returns ErrNoPrivateKey.
func Export(b Bundle, f Format, newPassphrase string) ([]byte, error) {
	switch f {
	case PEMBundle:
		return exportPEMBundle(b)
	case PEMCertOnly:
		return append([]byte{}, b.LeafPEM...), nil
	case PEMKeyOnly:
		if len(b.KeyPEM) == 0 {
			return nil, ErrNoPrivateKey
		}
		return append([]byte{}, b.KeyPEM...), nil
	case PEMFullchain:
		return exportPEMFullchain(b), nil
	case DER:
		return exportDER(b)
	case PKCS12:
		return exportPKCS12(b, newPassphrase)
	case PKCS7:
		return exportPKCS7(b)
	case JKS:
		return exportJKS(b, newPassphrase)
	default:
		return nil, ErrUnrecognizedFormat
	}
}

func exportPEMBundle(b Bundle) ([]byte, error) {
	if len(b.KeyPEM) == 0 {
		return nil, ErrNoPrivateKey
	}
	var out []byte
	out = append(out, b.LeafPEM...)
	out = append(out, b.KeyPEM...)
	for _, c := range b.ChainPEM {
		out = append(out, c...)
	}
	return out, nil
}

func exportPEMFullchain(b Bundle) []byte {
	var out []byte
	out = append(out, b.LeafPEM...)
	for _, c := range b.ChainPEM {
		out = append(out, c...)
	}
	return out
}

func exportDER(b Bundle) ([]byte, error) {
	leaf, _, err := leafAndChainCerts(b)
	if err != nil {
		return nil, err
	}
	return leaf.Raw, nil
}

func exportPKCS12(b Bundle, passphrase string) ([]byte, error) {
	leaf, chain, err := leafAndChainCerts(b)
	if err != nil {
		return nil, err
	}
	key, _, err := privateKey(b)
	if err != nil {
		return nil, err
	}
	return pkcs12.Modern.Encode(key, leaf, chain, passphrase)
}

func exportPKCS7(b Bundle) ([]byte, error) {
	leaf, chain, err := leafAndChainCerts(b)
	if err != nil {
		return nil, err
	}
	var concat []byte
	concat = append(concat, leaf.Raw...)
	for _, c := range chain {
		concat = append(concat, c.Raw...)
	}
	return pkcs7.DegenerateCertificate(concat)
}

func exportJKS(b Bundle, passphrase string) ([]byte, error) {
	leaf, chain, err := leafAndChainCerts(b)
	if err != nil {
		return nil, err
	}
	_, keyDER, err := privateKey(b)
	if err != nil {
		return nil, err
	}

	chainEntries := make([]keystore.Certificate, 0, len(chain)+1)
	chainEntries = append(chainEntries, keystore.Certificate{Type: "X509", Content: leaf.Raw})
	for _, c := range chain {
		chainEntries = append(chainEntries, keystore.Certificate{Type: "X509", Content: c.Raw})
	}

	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: chainEntries,
	}
	if err := ks.SetPrivateKeyEntry("certkit", entry, []byte(passphrase)); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(passphrase)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// leafAndChainCerts parses a Bundle's LeafPEM and ChainPEM into
// certificates.
func leafAndChainCerts(b Bundle) (*x509.Certificate, []*x509.Certificate, error) {
	leafBlock, _ := pem.Decode(b.LeafPEM)
	if leafBlock == nil {
		return nil, nil, ErrUnrecognizedFormat
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, nil, ErrUnrecognizedFormat
	}

	chain := make([]*x509.Certificate, 0, len(b.ChainPEM))
	for _, raw := range b.ChainPEM {
		block, _ := pem.Decode(raw)
		if block == nil {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		chain = append(chain, c)
	}

	return leaf, chain, nil
}

// privateKey parses a Bundle's KeyPEM (PKCS#8 PEM) into a crypto.PrivateKey,
// also returning its raw PKCS#8 DER bytes. It returns ErrNoPrivateKey if the
// Bundle has no key.
func privateKey(b Bundle) (crypto.PrivateKey, []byte, error) {
	if len(b.KeyPEM) == 0 {
		return nil, nil, ErrNoPrivateKey
	}
	block, _ := pem.Decode(b.KeyPEM)
	if block == nil {
		return nil, nil, ErrUnrecognizedFormat
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, ErrUnrecognizedFormat
	}
	return key, block.Bytes, nil
}
