package httpx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTraceOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	tr := traceOf(r)
	if tr.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || !tr.Sampled || tr.SpanID == "00f067aa0ba902b7" || len(tr.SpanID) != 16 {
		t.Errorf("from traceparent: %+v", tr)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Cloud-Trace-Context", "105445AA7843BC8BF206B12000100000/1;o=1")
	if tr := traceOf(r); tr.TraceID != "105445aa7843bc8bf206b12000100000" || !tr.Sampled {
		t.Errorf("from Google's header: %+v", tr)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("traceparent", "00-00000000000000000000000000000000-00f067aa0ba902b7-01")
	if tr := traceOf(r); len(tr.TraceID) != 32 || tr.TraceID == strings.Repeat("0", 32) {
		t.Errorf("an invalid traceparent starts a new trace: %+v", tr)
	}
}

// A request's trace reaches the call it makes, as a child span, and its log
// line names the trace.
func TestTraceFlowsThroughAService(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	var outgoing string
	h := Logged(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := httptest.NewRequest(http.MethodGet, "http://other/", nil)
		Propagate(r.Context(), req)
		outgoing = req.Header.Get("traceparent")
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), r)
	parts := strings.Split(outgoing, "-")
	if len(parts) != 4 || parts[1] != "4bf92f3577b34da6a3ce929d0e0e4736" || parts[3] != "01" || parts[2] == "00f067aa0ba902b7" {
		t.Errorf("outgoing traceparent %q", outgoing)
	}
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &line); err != nil {
		t.Fatal(err)
	}
	if line["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" && line["logging.googleapis.com/trace"] == nil {
		t.Errorf("log line without its trace: %v", line)
	}
}

func TestMetrics(t *testing.T) {
	mux := http.NewServeMux()
	Health(mux)
	mux.HandleFunc("GET /things/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	h := Logged(slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)), mux)
	for range 3 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/things/1", nil))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`http_requests_total{method="GET",route="GET /things/{id}",status="404"} 3`,
		`http_request_duration_seconds_count{method="GET",route="GET /things/{id}"} 3`,
		"process_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics without %q:\n%s", want, body)
		}
	}
	// Through the load balancer, the metrics are not there.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("metrics served through the load balancer: %d", rec.Code)
	}
}
