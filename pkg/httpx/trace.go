package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
)

// Distributed tracing, without an SDK: every request carries a W3C
// trace context, taken from the caller or begun here, and every call to
// another service passes it on as a child span. Each request's log line
// names its trace in the form Cloud Logging correlates, so one trace in
// Cloud Trace shows every hop and every log line of a request.

// Trace is a request's place in a distributed trace.
type Trace struct {
	TraceID string // 32 hex
	SpanID  string // 16 hex
	Sampled bool
}

type traceKey struct{}

// WithTrace is ctx carrying t.
func WithTrace(ctx context.Context, t Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

// TraceFrom is the trace ctx carries, if any.
func TraceFrom(ctx context.Context) (Trace, bool) {
	t, ok := ctx.Value(traceKey{}).(Trace)
	return t, ok
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isHex(s string, n int) bool {
	if len(s) != n || strings.Trim(s, "0") == "" {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// traceOf is the trace a request arrives with: a W3C traceparent, else
// Google's own header, else a new trace begun here.
func traceOf(r *http.Request) Trace {
	if parts := strings.Split(r.Header.Get("traceparent"), "-"); len(parts) == 4 && parts[0] == "00" && isHex(parts[1], 32) && isHex(parts[2], 16) {
		return Trace{TraceID: parts[1], SpanID: randomHex(8), Sampled: strings.HasSuffix(parts[3], "1")}
	}
	if h := r.Header.Get("X-Cloud-Trace-Context"); h != "" {
		id, rest, _ := strings.Cut(h, "/")
		if isHex(strings.ToLower(id), 32) {
			return Trace{TraceID: strings.ToLower(id), SpanID: randomHex(8), Sampled: strings.Contains(rest, "o=1")}
		}
	}
	return Trace{TraceID: randomHex(16), SpanID: randomHex(8), Sampled: false}
}

// Propagate puts ctx's trace on an outgoing request, as a child of this
// request's span.
func Propagate(ctx context.Context, req *http.Request) {
	t, ok := TraceFrom(ctx)
	if !ok {
		return
	}
	flags := "00"
	if t.Sampled {
		flags = "01"
	}
	req.Header.Set("traceparent", "00-"+t.TraceID+"-"+t.SpanID+"-"+flags)
}

// cloudProject is the project Cloud Logging correlates traces in; empty
// off Google Cloud, where the plain trace id is logged instead.
var cloudProject = firstNonEmpty(os.Getenv("GOOGLE_CLOUD_PROJECT"), os.Getenv("GCP_PROJECT"))

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// traceFields are the log attributes that tie a line to its trace.
func traceFields(t Trace) []any {
	if cloudProject == "" {
		return []any{"trace_id", t.TraceID, "span_id", t.SpanID}
	}
	return []any{
		"logging.googleapis.com/trace", "projects/" + cloudProject + "/traces/" + t.TraceID,
		"logging.googleapis.com/spanId", t.SpanID,
		"logging.googleapis.com/trace_sampled", t.Sampled,
	}
}
