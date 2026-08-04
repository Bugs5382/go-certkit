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

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

// Parse decodes data (in any supported container format) into a Bundle.
// passphrase is used to decrypt an encrypted private key, PKCS#12 archive or
// JKS/JCEKS keystore; pass "" when the input is not encrypted.
//
// If the container holds more than one distinct entry (e.g. a multi-alias
// JKS/JCEKS keystore, or a PKCS#7 bag with multiple leaf-like certificates)
// Parse returns *ErrMultipleEntries carrying the entries' aliases/subjects;
// use ParseEntry (JKS/JCEKS) to select one.
func Parse(data []byte, passphrase string) (Bundle, error) {
	// DetectFormat is a best-effort hint. When it confidently identifies a
	// format, trust its parser's result -- including a definitive error
	// like ErrWrongPassphrase or ErrMultipleEntries, which must propagate
	// rather than being masked by a fallback attempt. Only when the hint is
	// Unknown, or the matched parser itself reports the data doesn't
	// actually match that format, do we fall back to trying every parser in
	// turn.
	if format := DetectFormat(data); format != Unknown {
		b, err := parseByFormat(format, data, passphrase)
		if !errors.Is(err, ErrUnrecognizedFormat) {
			return b, err
		}
	}

	if bytes.Contains(data, []byte("-----BEGIN")) {
		return parsePEM(data, passphrase)
	}
	if b, err := parsePKCS12(data, passphrase); err == nil {
		return b, nil
	}
	if b, err := parsePKCS7(data); err == nil {
		return b, nil
	}
	if b, err := parseDER(data); err == nil {
		return b, nil
	}
	if b, err := parseJKS(data, passphrase); err == nil {
		return b, nil
	}

	return Bundle{}, ErrUnrecognizedFormat
}

// parseByFormat dispatches to the parser for an already-detected format.
func parseByFormat(format Format, data []byte, passphrase string) (Bundle, error) {
	switch format {
	case PEMBundle, PEMCertOnly, PEMKeyOnly, PEMFullchain:
		return parsePEM(data, passphrase)
	case DER:
		return parseDER(data)
	case JKS:
		return parseJKS(data, passphrase)
	case PKCS12:
		return parsePKCS12(data, passphrase)
	case PKCS7:
		return parsePKCS7(data)
	default:
		return Bundle{}, ErrUnrecognizedFormat
	}
}

// parsePEM decodes a PEM stream into a Bundle. Certificate blocks are
// classified leaf vs. chain by CA status (the first non-CA certificate is
// the leaf; everything else is chain); if every certificate is a CA, the
// first certificate found is treated as the leaf. At most one private key
// block is expected; if it is encrypted, passphrase decrypts it.
func parsePEM(data []byte, passphrase string) (Bundle, error) {
	var (
		certs    []*x509.Certificate
		certPEMs []*pem.Block
		keyPEM   []byte
	)

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch {
		case isCertificateBlock(block):
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
			certPEMs = append(certPEMs, block)
		case isPrivateKeyBlock(block):
			keyDER, err := decodePrivateKeyBlock(block, passphrase)
			if err != nil {
				return Bundle{}, err
			}
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		}
	}

	if len(certs) == 0 {
		return Bundle{}, ErrUnrecognizedFormat
	}

	leafIdx := 0
	for i, c := range certs {
		if !c.BasicConstraintsValid || !c.IsCA {
			leafIdx = i
			break
		}
	}

	leaf := certs[leafIdx]
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certPEMs[leafIdx].Bytes})

	var chainPEM [][]byte
	for i, block := range certPEMs {
		if i == leafIdx {
			continue
		}
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
	}

	return Bundle{
		LeafPEM:  leafPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
		Meta:     metaFromLeaf(leaf),
	}, nil
}

// parseDER decodes a single raw DER-encoded certificate into a cert-only
// Bundle (no key, no chain).
func parseDER(data []byte) (Bundle, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return Bundle{}, ErrUnrecognizedFormat
	}

	return Bundle{
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		Meta:    metaFromLeaf(cert),
	}, nil
}

func isCertificateBlock(b *pem.Block) bool {
	return b.Type == "CERTIFICATE" || b.Type == "TRUSTED CERTIFICATE"
}

func isPrivateKeyBlock(b *pem.Block) bool {
	switch b.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return true
	default:
		return false
	}
}

// decodePrivateKeyBlock normalizes any supported private-key PEM block to a
// plain PKCS#8 DER blob, decrypting it first if necessary.
func decodePrivateKeyBlock(block *pem.Block, passphrase string) ([]byte, error) {
	der := block.Bytes

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		plain, err := decryptPKCS8(der, passphrase)
		if err != nil {
			return nil, err
		}
		der = plain
	} else if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // legacy RFC 1423 PEM encryption, no non-deprecated stdlib alternative
		plain, err := x509.DecryptPEMBlock(block, []byte(passphrase)) //nolint:staticcheck // legacy RFC 1423 PEM encryption, no non-deprecated stdlib alternative
		if err != nil {
			return nil, ErrWrongPassphrase
		}
		der = plain
	}

	return normalizeToPKCS8(der)
}

// normalizeToPKCS8 re-encodes a private key DER blob (in PKCS#1, SEC1/EC or
// already-PKCS#8 form) as PKCS#8 DER.
func normalizeToPKCS8(der []byte) ([]byte, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		out, err := x509.MarshalPKCS8PrivateKey(key)
		if err == nil {
			return out, nil
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return x509.MarshalPKCS8PrivateKey(key)
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return x509.MarshalPKCS8PrivateKey(key)
	}

	return nil, ErrUnrecognizedFormat
}

// parsePKCS12 decodes a DER-encoded PKCS#12 (.p12/.pfx) archive into a
// Bundle. The first certificate is treated as the leaf and any remaining
// certificates as the chain, matching pkcs12.DecodeChain's convention.
func parsePKCS12(data []byte, passphrase string) (Bundle, error) {
	key, cert, caCerts, err := pkcs12.DecodeChain(data, passphrase)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Is(err, pkcs12.ErrDecryption) {
			return Bundle{}, ErrWrongPassphrase
		}
		return Bundle{}, ErrUnrecognizedFormat
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, ErrUnrecognizedFormat
	}

	chainPEM := make([][]byte, 0, len(caCerts))
	for _, c := range caCerts {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}

	return Bundle{
		LeafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		ChainPEM: chainPEM,
		Meta:     metaFromLeaf(cert),
	}, nil
}

// parsePKCS7 decodes a DER PKCS#7 certs-only bag (.p7b/.p7c) into a Bundle.
// PKCS#7 carries no private key. The single non-CA (end-entity) certificate
// is treated as the leaf and the rest as chain; if more than one end-entity
// certificate is present, the bag is ambiguous and ErrMultipleEntries is
// returned, carrying each candidate's subject as its "alias". If every
// certificate is a CA (no end-entity cert at all), the first certificate is
// used as the leaf.
func parsePKCS7(data []byte) (Bundle, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return Bundle{}, ErrUnrecognizedFormat
	}

	certs := p7.Certificates
	if len(certs) == 0 {
		return Bundle{}, ErrUnrecognizedFormat
	}

	var endEntity []int
	for i, c := range certs {
		if !c.BasicConstraintsValid || !c.IsCA {
			endEntity = append(endEntity, i)
		}
	}

	leafIdx := 0
	switch len(endEntity) {
	case 0:
		leafIdx = 0
	case 1:
		leafIdx = endEntity[0]
	default:
		aliases := make([]string, len(endEntity))
		for i, idx := range endEntity {
			aliases[i] = certs[idx].Subject.String()
		}
		return Bundle{}, &ErrMultipleEntries{Aliases: aliases}
	}

	leaf := certs[leafIdx]

	var chainPEM [][]byte
	for i, c := range certs {
		if i == leafIdx {
			continue
		}
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}

	return Bundle{
		LeafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		ChainPEM: chainPEM,
		Meta:     metaFromLeaf(leaf),
	}, nil
}

// parseJKS decodes a JKS/JCEKS keystore. A keystore with exactly one alias
// is returned directly as a Bundle; one with more than one alias is
// ambiguous, and ErrMultipleEntries (carrying the aliases) is returned so
// the caller can pick one via ParseEntry.
func parseJKS(data []byte, passphrase string) (Bundle, error) {
	ks, err := loadKeystore(data, passphrase)
	if err != nil {
		return Bundle{}, err
	}

	aliases := ks.Aliases()
	switch len(aliases) {
	case 0:
		return Bundle{}, ErrUnrecognizedFormat
	case 1:
		return bundleFromKeystoreEntry(ks, aliases[0], passphrase)
	default:
		return Bundle{}, &ErrMultipleEntries{Aliases: aliases}
	}
}

// ParseEntry decodes the named alias of a JKS/JCEKS keystore into a Bundle.
// Use it after Parse reports *ErrMultipleEntries for a multi-alias
// keystore.
func ParseEntry(data []byte, passphrase, alias string) (Bundle, error) {
	ks, err := loadKeystore(data, passphrase)
	if err != nil {
		return Bundle{}, err
	}
	return bundleFromKeystoreEntry(ks, alias, passphrase)
}

// loadKeystore decodes the JKS/JCEKS container framing. Any failure --
// wrong store passphrase or a corrupt/foreign file -- is reported as
// ErrWrongPassphrase, since JKS has no separate integrity signal from its
// password-derived check.
func loadKeystore(data []byte, passphrase string) (keystore.KeyStore, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(passphrase)); err != nil {
		return keystore.KeyStore{}, ErrWrongPassphrase
	}
	return ks, nil
}

// bundleFromKeystoreEntry extracts a single named alias -- a PrivateKeyEntry
// (key + leaf + chain) or a TrustedCertificateEntry (cert only) -- as a
// Bundle.
func bundleFromKeystoreEntry(ks keystore.KeyStore, alias, passphrase string) (Bundle, error) {
	switch {
	case ks.IsPrivateKeyEntry(alias):
		entry, err := ks.GetPrivateKeyEntry(alias, []byte(passphrase))
		if err != nil {
			return Bundle{}, ErrWrongPassphrase
		}
		if len(entry.CertificateChain) == 0 {
			return Bundle{}, ErrUnrecognizedFormat
		}

		keyDER, err := normalizeToPKCS8(entry.PrivateKey)
		if err != nil {
			return Bundle{}, err
		}

		leaf, err := x509.ParseCertificate(entry.CertificateChain[0].Content)
		if err != nil {
			return Bundle{}, ErrUnrecognizedFormat
		}

		var chainPEM [][]byte
		for _, c := range entry.CertificateChain[1:] {
			chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Content}))
		}

		return Bundle{
			LeafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
			KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
			ChainPEM: chainPEM,
			Meta:     metaFromLeaf(leaf),
		}, nil

	case ks.IsTrustedCertificateEntry(alias):
		entry, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			return Bundle{}, ErrUnrecognizedFormat
		}
		cert, err := x509.ParseCertificate(entry.Certificate.Content)
		if err != nil {
			return Bundle{}, ErrUnrecognizedFormat
		}
		return Bundle{
			LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
			Meta:    metaFromLeaf(cert),
		}, nil

	default:
		return Bundle{}, ErrUnrecognizedFormat
	}
}
