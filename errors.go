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
	"fmt"
	"strings"
)

// Sentinel errors returned by Parse, ParseEntry and Export.
var (
	// ErrWrongPassphrase is returned when the supplied passphrase fails to
	// decrypt an encrypted private key, PKCS#12 archive or JKS/JCEKS
	// keystore.
	ErrWrongPassphrase = errors.New("certkit: wrong passphrase")

	// ErrUnrecognizedFormat is returned when the input does not match any
	// supported container format.
	ErrUnrecognizedFormat = errors.New("certkit: unrecognized format")

	// ErrNoPrivateKey is returned when a caller requests a key-bearing
	// export (e.g. PKCS#12, JKS) from a Bundle that has no private key.
	ErrNoPrivateKey = errors.New("certkit: no private key")
)

// ErrMultipleEntries is returned by Parse when a container holds more than
// one distinct end-entity entry (e.g. a multi-alias JKS/JCEKS keystore or a
// PKCS#7 bag with more than one leaf-like certificate) and the caller must
// pick one explicitly -- via ParseEntry for JKS/JCEKS.
type ErrMultipleEntries struct {
	Aliases []string
}

// Error implements the error interface.
func (e *ErrMultipleEntries) Error() string {
	return fmt.Sprintf("certkit: multiple entries found, select one of: %s", strings.Join(e.Aliases, ", "))
}
