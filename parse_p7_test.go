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
	"errors"
	"testing"

	"go.mozilla.org/pkcs7"
)

func makeTestP7B(t *testing.T, certsDER ...[]byte) []byte {
	t.Helper()
	var concat []byte
	for _, c := range certsDER {
		concat = append(concat, c...)
	}
	data, err := pkcs7.DegenerateCertificate(concat)
	if err != nil {
		t.Fatalf("build PKCS#7 degenerate certificate: %v", err)
	}
	return data
}

func TestParsePKCS7(t *testing.T) {
	tc := makeTestChain(t)
	p7b := makeTestP7B(t, tc.LeafCert.Raw, tc.IntermCert.Raw)

	b, err := Parse(p7b, "")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(b.KeyPEM) != 0 {
		t.Errorf("KeyPEM = %q, want empty (PKCS#7 carries no key)", b.KeyPEM)
	}
	if len(b.ChainPEM) != 1 {
		t.Fatalf("len(ChainPEM) = %d, want 1", len(b.ChainPEM))
	}
	if b.Meta.Subject == "" {
		t.Error("Meta.Subject is empty, want it set")
	}
}

func TestParsePKCS7MultipleEntries(t *testing.T) {
	tc1 := makeTestChain(t)
	tc2 := makeTestChain(t)
	p7b := makeTestP7B(t, tc1.LeafCert.Raw, tc2.LeafCert.Raw)

	_, err := Parse(p7b, "")

	var multi *ErrMultipleEntries
	if !errors.As(err, &multi) {
		t.Fatalf("Parse() error = %v, want *ErrMultipleEntries", err)
	}
	if len(multi.Aliases) != 2 {
		t.Fatalf("len(Aliases) = %d, want 2: %v", len(multi.Aliases), multi.Aliases)
	}
	if multi.Aliases[0] != tc1.LeafCert.Subject.String() || multi.Aliases[1] != tc2.LeafCert.Subject.String() {
		t.Errorf("Aliases = %v, want both leaf subjects", multi.Aliases)
	}
}
