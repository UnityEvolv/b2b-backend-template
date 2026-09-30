package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
)

// sse is one open stream: its events, as they arrive.
type sse struct {
	events chan map[string]any
	names  chan string
	closed chan struct{}
}

// stream opens GET /v1/session/events as the browser b, and waits for ready.
func stream(t *testing.T, srv *httptest.Server, b *browser) *sse {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/session/events", nil)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	s := &sse{events: make(chan map[string]any, 16), names: make(chan string, 16), closed: make(chan struct{})}
	go func() {
		defer close(s.closed)
		defer resp.Body.Close()
		r := bufio.NewReader(resp.Body)
		name := ""
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				var data map[string]any
				_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &data)
				s.names <- name
				s.events <- data
			}
		}
	}()
	if name, _ := s.next(t, 5*time.Second); name != "ready" {
		t.Fatalf("the stream did not open with ready: %q", name)
	}
	return s
}

func (s *sse) next(t *testing.T, within time.Duration) (string, map[string]any) {
	t.Helper()
	select {
	case name := <-s.names:
		return name, <-s.events
	case <-time.After(within):
		return "", nil
	}
}

// B2B-25: revoking a session reaches that session's open stream within
// seconds, over the live-session bus in Redis, and ends it; the same
// person's other session and somebody else's hear nothing. A stream opened
// for a session already over is told so at once.
func TestRevocationReachesTheOpenSession(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { rdb.Close() })

	f := newAPI(t)
	f.configure(acme)
	// Its own channel, so parallel runs do not hear each other.
	names := config.Redis{Prefix: "test-" + uuid.NewString()}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := livebus.NewBus(rdb, names.LiveEvents(), nil, logger)
	f.events.mu.Lock()
	f.events.bus = bus
	f.events.mu.Unlock()
	f.srv.WithLive(bus)
	srv := httptest.NewServer(httpx.Logged(logger, f.srv.SessionEvents()))
	t.Cleanup(srv.Close)

	laptop, token := signedIn(t, f, "ada@acme.com")
	phone, _ := signedIn(t, f, "ada@acme.com")
	bob, _ := signedIn(t, f, "bob@acme.com")
	var phoneSession string
	for _, raw := range body(t, laptop.do(http.MethodGet, "/v1/sessions", token, nil))["sessions"].([]any) {
		if s := raw.(map[string]any); s["current"] != true {
			phoneSession = s["session_id"].(string)
		}
	}
	laptopStream, phoneStream, bobStream := stream(t, srv, laptop), stream(t, srv, phone), stream(t, srv, bob)

	start := time.Now()
	if rec := laptop.do(http.MethodDelete, "/v1/sessions/"+phoneSession, token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	name, ev := phoneStream.next(t, 5*time.Second)
	if name != "session.revoked" || ev["session_id"] != phoneSession || ev["scope"] != "session" || ev["code"] != "revoked" || ev["message"] == "" {
		t.Fatalf("the phone's stream: %q %v", name, ev)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("revocation took %v to arrive", took)
	}
	select {
	case <-phoneStream.closed:
	case <-time.After(5 * time.Second):
		t.Error("the revoked session's stream stayed open")
	}
	if name, ev := laptopStream.next(t, 500*time.Millisecond); name != "" {
		t.Errorf("the laptop heard %q %v", name, ev)
	}
	if name, ev := bobStream.next(t, 100*time.Millisecond); name != "" {
		t.Errorf("someone else heard %q %v", name, ev)
	}

	// Opened again with the dead cookie: told at once, and closed.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/session/events", nil)
	for _, c := range phone.cookies {
		req.AddCookie(c)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "event: session.revoked") {
		t.Errorf("a stream for an ended session: %d %s", resp.StatusCode, raw)
	}
	// No cookie at all: not signed in.
	resp, err = srv.Client().Get(srv.URL + "/v1/session/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a stream without a session: %d", resp.StatusCode)
	}
}
