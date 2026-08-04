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
)

func TestParseGarbageUnrecognized(t *testing.T) {
	garbage := []byte("this is not a certificate at all, just some plain text")

	_, err := Parse(garbage, "")
	if !errors.Is(err, ErrUnrecognizedFormat) {
		t.Fatalf("Parse(garbage) error = %v, want ErrUnrecognizedFormat", err)
	}
}

func TestParseTruncatedASN1(t *testing.T) {
	// An ASN.1 SEQUENCE (0x30) declaring a long-form length of 1000 bytes
	// (0x82 0x03 0xE8) but carrying only a couple: a truncated DER blob.
	truncated := []byte{0x30, 0x82, 0x03, 0xE8, 0x01, 0x02}

	_, err := Parse(truncated, "")
	if !errors.Is(err, ErrUnrecognizedFormat) {
		t.Fatalf("Parse(truncated ASN.1) error = %v, want ErrUnrecognizedFormat", err)
	}
}
