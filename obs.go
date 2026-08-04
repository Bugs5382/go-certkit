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

// Optional observability for the context-aware Parse/Export/ParseEntry
// variants. Both are opt-in and off by default: with no options the ctx
// variants (and therefore the simple wrappers) emit nothing at all.
//
// SECURITY: no passphrase, private-key bytes, or raw input bytes are ever
// logged or placed on a span. Only non-sensitive attributes -- the detected
// or requested format, byte sizes, chain length, whether a private key is
// present, and public certificate metadata (subject, serial, notAfter) -- are
// recorded.

import (
	"context"
	"fmt"

	golog "github.com/Bugs5382/go-log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation scope for spans this package starts.
const tracerName = "github.com/Bugs5382/go-certkit"

// Option configures the optional logging/tracing of a context-aware call.
type Option func(*obsConfig)

// obsConfig holds the resolved observability settings for one call. It is
// unexported: callers configure it only through Option values.
type obsConfig struct {
	logger  golog.Logger
	tracing bool
}

// WithLogger injects a go-log neutral Logger. Success is logged at debug
// level and failure at error level (with the typed error); both carry only
// non-sensitive attributes.
func WithLogger(l golog.Logger) Option {
	return func(c *obsConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithTracing enables a single OpenTelemetry span around the operation,
// started from the global TracerProvider. It is a no-op unless the
// application has installed a provider.
func WithTracing() Option {
	return func(c *obsConfig) { c.tracing = true }
}

// newObsConfig resolves opts, defaulting the logger to a no-op so call sites
// never need a nil check.
func newObsConfig(opts ...Option) *obsConfig {
	c := &obsConfig{logger: nopLogger{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// obsAttr is a neutral, non-sensitive key/value recorded on both the span and
// the log line.
type obsAttr struct {
	key string
	val any
}

// observe runs op under the configured logging/tracing. name is the span and
// log operation name (e.g. "certkit.Parse"). attrs builds the non-sensitive
// attributes from the outcome; it must never return sensitive values.
func observe[T any](
	ctx context.Context,
	c *obsConfig,
	name string,
	op func(context.Context) (T, error),
	attrs func(T, error) []obsAttr,
) (T, error) {
	ctx, span := c.startSpan(ctx, name)
	defer endSpan(span)

	res, err := op(ctx)

	kvs := attrs(res, err)
	setSpanAttrs(span, kvs)

	if err != nil {
		recordSpanError(span, err)
		c.logger.Ctx(ctx).Error(err, name+" failed", toLogFields(kvs)...)
		return res, err
	}

	c.logger.Ctx(ctx).Debug(name+" succeeded", toLogFields(kvs)...)
	return res, nil
}

// startSpan starts a span when tracing is enabled, otherwise returns ctx
// unchanged and a nil span.
func (c *obsConfig) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if !c.tracing {
		return ctx, nil
	}
	return otel.Tracer(tracerName).Start(ctx, name)
}

// endSpan ends span when non-nil.
func endSpan(span trace.Span) {
	if span != nil {
		span.End()
	}
}

// recordSpanError records err on span and marks it as failed.
func recordSpanError(span trace.Span, err error) {
	if span == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// setSpanAttrs attaches the neutral attributes to span when non-nil.
func setSpanAttrs(span trace.Span, kvs []obsAttr) {
	if span == nil {
		return
	}
	attrs := make([]attribute.KeyValue, 0, len(kvs))
	for _, kv := range kvs {
		attrs = append(attrs, spanAttr(kv.key, kv.val))
	}
	span.SetAttributes(attrs...)
}

// spanAttr converts a neutral attribute to a typed OpenTelemetry attribute.
func spanAttr(key string, val any) attribute.KeyValue {
	switch t := val.(type) {
	case string:
		return attribute.String(key, t)
	case bool:
		return attribute.Bool(key, t)
	case int:
		return attribute.Int(key, t)
	case int64:
		return attribute.Int64(key, t)
	default:
		return attribute.String(key, fmt.Sprintf("%v", t))
	}
}

// toLogFields converts the neutral attributes to go-log structured fields.
func toLogFields(kvs []obsAttr) []golog.Field {
	fields := make([]golog.Field, 0, len(kvs))
	for _, kv := range kvs {
		fields = append(fields, golog.F(kv.key, kv.val))
	}
	return fields
}

// nopLogger is a go-log Logger that discards everything. It is the default
// when no logger is injected, so the observability path is safe to call
// unconditionally and emits nothing by default.
type nopLogger struct{}

func (nopLogger) Debug(string, ...golog.Field)        {}
func (nopLogger) Info(string, ...golog.Field)         {}
func (nopLogger) Warn(string, ...golog.Field)         {}
func (nopLogger) Error(error, string, ...golog.Field) {}
func (nopLogger) Fatal(error, string, ...golog.Field) {}
func (n nopLogger) With(...golog.Field) golog.Logger  { return n }
func (n nopLogger) Ctx(context.Context) golog.Logger  { return n }
