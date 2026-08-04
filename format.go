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
	"encoding/binary"
	"encoding/pem"
	"strings"
)

// Format identifies a certificate/key container format.
type Format int

// Unknown is returned by DetectFormat when the input cannot be classified.
const Unknown Format = Format(-1)

// Supported container formats.
const (
	PKCS12 Format = iota
	PEMBundle
	PEMCertOnly
	PEMKeyOnly
	PEMFullchain
	DER
	PKCS7
	JKS
)

// jksMagic and jceksMagic are the 4-byte magic numbers at the start of a Java
// KeyStore / JCE KeyStore file.
const (
	jksMagic   = 0xFEEDFEED
	jceksMagic = 0xCECECECE
)

// pkcs12OID and pkcs7SignedDataOID are the raw (tag/length-stripped) DER arc
// bytes for the pkcs-12 (1.2.840.113549.1.12) and pkcs7-signedData
// (1.2.840.113549.1.7.2) object identifiers. DetectFormat uses their presence
// as a best-effort, non-authoritative hint that a binary blob is PKCS#12 or
// PKCS#7 -- Parse still tries the real parsers to confirm.
var (
	pkcs12OID          = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C}
	pkcs7SignedDataOID = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
)

// DetectFormat returns a best-effort guess of the container format of data.
// It returns Unknown if no format could be identified. Parse does not rely
// on this being authoritative -- it dispatches on the hint but falls back to
// trying other parsers.
func DetectFormat(data []byte) Format {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return detectPEM(data)
	}

	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		if magic == jksMagic || magic == jceksMagic {
			return JKS
		}
	}

	if bytes.Contains(data, pkcs12OID) {
		return PKCS12
	}

	if bytes.Contains(data, pkcs7SignedDataOID) {
		return PKCS7
	}

	if _, err := x509.ParseCertificate(data); err == nil {
		return DER
	}

	return Unknown
}

// detectPEM classifies PEM-encoded data by the mix of certificate and
// private-key blocks it contains.
func detectPEM(data []byte) Format {
	var certCount, keyCount int

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			keyCount++
		case strings.Contains(block.Type, "CERTIFICATE"):
			certCount++
		}
	}

	switch {
	case keyCount > 0 && certCount > 0:
		return PEMBundle
	case keyCount > 0:
		return PEMKeyOnly
	case certCount > 1:
		return PEMFullchain
	case certCount == 1:
		return PEMCertOnly
	default:
		return Unknown
	}
}
