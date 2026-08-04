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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	golog "github.com/Bugs5382/go-log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// captureLogger is a buffer-backed go-log Logger for tests. It renders every
// call (message, error, and all fields) into a single buffer so a test can
// assert what was -- and was not -- logged.
type captureLogger struct{ buf *bytes.Buffer }

func newCaptureLogger() *captureLogger { return &captureLogger{buf: &bytes.Buffer{}} }

func (c *captureLogger) write(level, msg string, err error, fields []golog.Field) {
	fmt.Fprintf(c.buf, "%s msg=%q", level, msg)
	if err != nil {
		fmt.Fprintf(c.buf, " error=%q", err.Error())
	}
	for _, f := range fields {
		fmt.Fprintf(c.buf, " %s=%v", f.Key, f.Val)
	}
	c.buf.WriteByte('\n')
}

func (c *captureLogger) Debug(msg string, fields ...golog.Field) { c.write("debug", msg, nil, fields) }
func (c *captureLogger) Info(msg string, fields ...golog.Field)  { c.write("info", msg, nil, fields) }
func (c *captureLogger) Warn(msg string, fields ...golog.Field)  { c.write("warn", msg, nil, fields) }
func (c *captureLogger) Error(err error, msg string, fields ...golog.Field) {
	c.write("error", msg, err, fields)
}
func (c *captureLogger) Fatal(err error, msg string, fields ...golog.Field) {
	c.write("fatal", msg, err, fields)
}
func (c *captureLogger) With(...golog.Field) golog.Logger { return c }
func (c *captureLogger) Ctx(context.Context) golog.Logger { return c }

const testPassphrase = "topsecret-pass"

func TestParseContextLoggerNoSecretLeak(t *testing.T) {
	tc := makeTestChain(t)
	// A PKCS#12 archive protected by a known passphrase: the passphrase is
	// required to parse, so if it were going to leak anywhere it would be here.
	p12 := makeTestP12(t, tc, testPassphrase)

	logger := newCaptureLogger()
	b, err := ParseContext(context.Background(), p12, testPassphrase, WithLogger(logger))
	if err != nil {
		t.Fatalf("ParseContext() error = %v", err)
	}

	out := logger.buf.String()
	if out == "" {
		t.Fatal("expected a log line, got none")
	}
	if !strings.Contains(out, "certkit.Parse succeeded") {
		t.Errorf("log missing success message; got: %s", out)
	}

	// SECURITY: the passphrase must never appear in the log output.
	if strings.Contains(out, testPassphrase) {
		t.Fatalf("passphrase leaked into log output: %s", out)
	}
	// Nor may raw private-key PEM material appear.
	if bytes.Contains(logger.buf.Bytes(), b.KeyPEM) {
		t.Fatal("private key material leaked into log output")
	}
	// The public subject metadata is expected to be present.
	if !strings.Contains(out, "leaf.example.com") {
		t.Errorf("expected the public subject in the log; got: %s", out)
	}
}

func TestParseContextTracingSpan(t *testing.T) {
	rec := newTracerProvider(t)

	tc := makeTestChain(t)
	if _, err := ParseContext(context.Background(), makePEMBundle(t, tc), "", WithTracing()); err != nil {
		t.Fatalf("ParseContext() error = %v", err)
	}

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want exactly 1", len(spans))
	}
	if got := spans[0].Name(); got != "certkit.Parse" {
		t.Errorf("span name = %q, want certkit.Parse", got)
	}
	if got := spans[0].Status().Code; got != codes.Unset {
		t.Errorf("span status = %v, want Unset for a success", got)
	}
	// The format attribute must still be populated on the observed path.
	if got := spanStringAttr(spans[0], "certkit.format"); got != "pem" {
		t.Errorf("span certkit.format = %q, want pem", got)
	}
}

func TestParseContextTracingErrorStatus(t *testing.T) {
	rec := newTracerProvider(t)

	tc := makeTestChain(t)
	p12 := makeTestP12(t, tc, testPassphrase)

	// Wrong passphrase -> error -> span must carry error status.
	if _, err := ParseContext(context.Background(), p12, "wrong", WithTracing()); err == nil {
		t.Fatal("expected an error from a wrong passphrase")
	}

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want exactly 1", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("span status = %v, want Error", got)
	}
}

func TestExportContextTracingSpan(t *testing.T) {
	rec := newTracerProvider(t)

	b := testBundle(t)
	if _, err := ExportContext(context.Background(), b, PEMBundle, "", WithTracing()); err != nil {
		t.Fatalf("ExportContext() error = %v", err)
	}

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want exactly 1", len(spans))
	}
	if got := spans[0].Name(); got != "certkit.Export" {
		t.Errorf("span name = %q, want certkit.Export", got)
	}
}

func TestExportContextTracingErrorStatus(t *testing.T) {
	rec := newTracerProvider(t)

	// Cert-only bundle exported to a key-bearing format -> ErrNoPrivateKey.
	tc := makeTestChain(t)
	certOnly := Bundle{LeafPEM: certPEM(tc.LeafCert), Meta: metaFromLeaf(tc.LeafCert)}
	if _, err := ExportContext(context.Background(), certOnly, PKCS12, "pw", WithTracing()); err == nil {
		t.Fatal("expected ErrNoPrivateKey")
	}

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want exactly 1", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("span status = %v, want Error", got)
	}
}

func TestNoOptsEmitsNothing(t *testing.T) {
	rec := newTracerProvider(t)
	logger := newCaptureLogger()

	tc := makeTestChain(t)
	pemBundle := makePEMBundle(t, tc)

	// Plain Parse / Export (no opts) must behave identically and emit nothing:
	// no spans recorded, and (implicitly) the default no-op logger is used.
	want, err := Parse(pemBundle, "")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	got, err := ParseContext(context.Background(), pemBundle, "")
	if err != nil {
		t.Fatalf("ParseContext() error = %v", err)
	}
	if !bytes.Equal(want.LeafPEM, got.LeafPEM) || !bytes.Equal(want.KeyPEM, got.KeyPEM) {
		t.Error("Parse and ParseContext (no opts) returned different results")
	}

	if spans := rec.Ended(); len(spans) != 0 {
		t.Fatalf("expected zero spans with no WithTracing, got %d", len(spans))
	}
	// The injected logger was never wired in (no WithLogger), so nothing was
	// captured through it.
	if logger.buf.Len() != 0 {
		t.Fatalf("expected no log output without WithLogger, got: %s", logger.buf.String())
	}
}

func TestNoOptsDERStillParses(t *testing.T) {
	// Guard against the no-opts short-circuit accidentally skipping real
	// work: plain Parse of a bare DER certificate (which exercises
	// DetectFormat's x509 fallback) must still return a correct Bundle.
	tc := makeTestChain(t)

	b, err := Parse(tc.LeafCert.Raw, "")
	if err != nil {
		t.Fatalf("Parse(DER) error = %v", err)
	}

	if b.Meta.Subject != "CN=leaf.example.com" {
		t.Errorf("Meta.Subject = %q, want CN=leaf.example.com", b.Meta.Subject)
	}
	if len(b.KeyPEM) != 0 {
		t.Errorf("KeyPEM = %q, want empty for a bare DER cert", b.KeyPEM)
	}
	if len(b.ChainPEM) != 0 {
		t.Errorf("len(ChainPEM) = %d, want 0", len(b.ChainPEM))
	}

	block, _ := pem.Decode(b.LeafPEM)
	if block == nil {
		t.Fatal("LeafPEM did not decode as PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("LeafPEM did not parse: %v", err)
	}
	if !bytes.Equal(leaf.Raw, tc.LeafCert.Raw) {
		t.Error("parsed leaf does not match the input DER certificate")
	}
}

// spanStringAttr returns the string value of the named span attribute, or ""
// when absent.
func spanStringAttr(span sdktrace.ReadOnlySpan, key string) string {
	for _, kv := range span.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}

// newTracerProvider installs an in-memory span recorder as the global tracer
// provider for the duration of a test and returns the recorder.
func newTracerProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return rec
}
