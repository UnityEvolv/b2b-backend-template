package errtrack_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
)

// A transport that keeps what would have been sent.
type memory struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (m *memory) Configure(sentry.ClientOptions) {}
func (m *memory) SendEvent(e *sentry.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}
func (m *memory) Flush(time.Duration) bool { return true }
func (m *memory) FlushWithContext(context.Context) bool {
	return true
}
func (m *memory) Close() {}
func (m *memory) all() []*sentry.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*sentry.Event{}, m.events...)
}

func start(t *testing.T) *memory {
	t.Helper()
	sink := &memory{}
	flush, err := errtrack.Init(errtrack.Options{
		DSN: "https://key@o1.ingest.sentry.io/1", Environment: "test", Service: "organization", Transport: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(flush)
	return sink
}

func TestErrorsCarryTheContextTags(t *testing.T) {
	sink := start(t)
	ctx := errtrack.WithTags(context.Background(), map[string]string{
		"request_id": "req-1", "org_id": "org-1", "user_id": "user-1", "membership_id": "m-1",
	})
	errtrack.Capture(ctx, errors.New("boom"))

	events := sink.all()
	if len(events) != 1 {
		t.Fatalf("events: %d", len(events))
	}
	e := events[0]
	for k, want := range map[string]string{"request_id": "req-1", "org_id": "org-1", "service": "organization"} {
		if e.Tags[k] != want {
			t.Errorf("tag %s = %q, want %q", k, e.Tags[k], want)
		}
	}
	if e.User.ID != "user-1" || e.Environment != "test" || e.Release == "" || e.ServerName != "organization" {
		t.Errorf("user %+v env %q release %q server %q", e.User, e.Environment, e.Release, e.ServerName)
	}
	if len(e.Exception) == 0 || e.Exception[0].Value != "boom" {
		t.Errorf("exception %+v", e.Exception)
	}
}

func TestLogRecordsAreForwardedByLevel(t *testing.T) {
	sink := start(t)
	logger := slog.New(errtrack.Handler(slog.NewTextHandler(nopWriter{}, nil))).With("service", "organization")
	ctx := errtrack.WithTags(context.Background(), map[string]string{"org_id": "org-9"})

	logger.InfoContext(ctx, "not sent")
	logger.WarnContext(ctx, "not sent either", "rule", "read")
	logger.WarnContext(ctx, "rate limited", "rule", "read", "alert", true)
	logger.ErrorContext(ctx, "request failed", "route", "GET /x", "error", errors.New("db down"))

	events := sink.all()
	if len(events) != 2 {
		t.Fatalf("events: %d", len(events))
	}
	warn, errEvent := events[0], events[1]
	if warn.Level != sentry.LevelWarning || warn.Message != "rate limited" || warn.Tags["rule"] != "read" || warn.Tags["org_id"] != "org-9" {
		t.Errorf("warning event: %+v", warn)
	}
	if errEvent.Level != sentry.LevelError || !strings.Contains(errEvent.Message, "db down") || errEvent.Tags["route"] != "GET /x" {
		t.Errorf("error event: %+v", errEvent)
	}
}

func TestPanicsAreCapturedWithAStack(t *testing.T) {
	sink := start(t)
	func() {
		defer func() { errtrack.CapturePanic(context.Background(), recover()) }()
		panic("nil map write")
	}()
	events := sink.all()
	if len(events) != 1 || len(events[0].Exception) == 0 || events[0].Exception[0].Stacktrace == nil {
		t.Fatalf("panic event: %+v", events)
	}
}

func TestNothingPrivateLeaves(t *testing.T) {
	sink := start(t)
	hub := sentry.CurrentHub().Clone()
	hub.ConfigureScope(func(s *sentry.Scope) {
		s.SetUser(sentry.User{ID: "u1", Email: "alice@example.com", IPAddress: "203.0.113.5", Name: "Alice"})
		req, _ := http.NewRequest(http.MethodPost, "/v1/things", strings.NewReader("secret body"))
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("Cookie", "session=abc")
		s.SetRequest(req)
	})
	hub.CaptureMessage("with a user")

	events := sink.all()
	if len(events) != 1 {
		t.Fatalf("events: %d", len(events))
	}
	u := events[0].User
	if u.ID != "u1" || u.Email != "" || u.IPAddress != "" || u.Name != "" {
		t.Errorf("user left with PII: %+v", u)
	}
	if r := events[0].Request; r == nil || r.Headers["Authorization"] != "" || r.Headers["Cookie"] != "" || r.Cookies != "" || r.Data != "" {
		t.Errorf("request left with secrets: %+v", r)
	}
}

func TestDisabledWithoutADSN(t *testing.T) {
	flush, err := errtrack.Init(errtrack.Options{})
	if err != nil || errtrack.Enabled() {
		t.Fatalf("no DSN: err %v enabled %v", err, errtrack.Enabled())
	}
	flush()
	errtrack.Capture(context.Background(), errors.New("ignored"))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
