package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
)

// NewMux is a router whose unmatched paths answer in the error envelope rather
// than with Go's plain-text 404, so every response a client sees has one shape.
func NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		WriteError(w, http.StatusNotFound, CodeNotFound, "Nothing here.")
	})
	return mux
}

// Check is one dependency a service needs before it can take traffic.
type Check struct {
	Name  string
	Check func(context.Context) error
}

// Health mounts the two probes every service answers, and its metrics.
//
//	/healthz  the process is up; never touches a dependency
//	/readyz   every check passes; a load balancer stops sending traffic otherwise
//	/metrics  request and process metrics, to a direct scrape only
func Health(mux *http.ServeMux, checks ...Check) {
	// Request rate, latency, errors and resource use.
	mux.HandleFunc("GET /metrics", metricsHandler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		failing := map[string]string{}
		for _, c := range checks {
			if err := c.Check(ctx); err != nil {
				failing[c.Name] = "unavailable"
			}
		}
		if len(failing) > 0 {
			WriteJSON(w, http.StatusServiceUnavailable, Error{Code: CodeUnavailable, Message: "Not ready.", Fields: failing})
			return
		}
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Unwrap is the writer underneath, so http.ResponseController reaches its
// Flush and deadlines: a stream (Server-Sent Events) works through Logged.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Logged logs one line per request and turns a panic into the error envelope.
//
// It logs the route pattern, never the raw path, so ids in URLs are not
// multiplied into log cardinality, and never a body.
func Logged(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		trace := traceOf(r)
		serviceMetrics.inFlight.Add(1)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		ctx := WithTrace(context.WithValue(r.Context(), requestInfoKey{}, RequestInfo{ID: id, ClientIP: ClientIP(r)}), trace)
		r = r.WithContext(errtrack.WithTags(ctx, map[string]string{"request_id": id, "route": r.Pattern}))

		defer func() {
			if p := recover(); p != nil {
				errtrack.CapturePanic(r.Context(), p)
				logger.Error("panic", "request_id", id, "panic", p, "stack", string(debug.Stack()))
				WriteError(rec, http.StatusInternalServerError, CodeInternal, "Something went wrong.")
			}
			elapsed := time.Since(start)
			serviceMetrics.inFlight.Add(-1)
			serviceMetrics.observe(r.Method, r.Pattern, rec.status, elapsed)
			logger.Info("request", append([]any{
				"request_id", id,
				"method", r.Method,
				"route", r.Pattern,
				"status", rec.status,
				"duration_ms", elapsed.Milliseconds(),
			}, traceFields(trace)...)...)
		}()
		next.ServeHTTP(rec, r)
	})
}

// RequestInfo is what a handler may need to know about the request it is in,
// beyond the caller: the id every log line and audit entry carries, and the
// address the request came from.
type RequestInfo struct {
	ID       string
	ClientIP string
}

type requestInfoKey struct{}

// RequestInfoFrom is the request info Logged put in ctx.
func RequestInfoFrom(ctx context.Context) RequestInfo {
	info, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Serve runs handler on addr until ctx ends, then stops taking new requests
// and gives in-flight ones up to grace to finish.
func Serve(ctx context.Context, logger *slog.Logger, addr string, handler http.Handler, grace time.Duration) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	failed := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
		close(failed)
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down", "grace", grace.String())
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), grace)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return err
	}
	return <-failed
}
