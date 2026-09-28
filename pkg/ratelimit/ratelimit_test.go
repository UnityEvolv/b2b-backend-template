package ratelimit_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// limiter needs a real Redis from TEST_REDIS_URL; without it the test skips.
func limiter(t *testing.T) *ratelimit.Limiter {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { rdb.Close() })
	return ratelimit.New(rdb, quiet)
}

// rule is r with a name no other test run uses, so buckets never collide.
func rule(r ratelimit.Rule) ratelimit.Rule {
	r.Name = r.Name + "-" + uuid.NewString()
	return r
}

func TestAllowsTheLimitThenRefuses(t *testing.T) {
	l := limiter(t)
	r := rule(ratelimit.Rule{Name: "burst", Limit: 5, Window: time.Second})
	ctx := context.Background()

	for i := range 5 {
		v, err := l.Take(ctx, r, "k")
		if err != nil || !v.Allowed {
			t.Fatalf("request %d: %+v %v", i+1, v, err)
		}
		if v.Remaining != 4-i {
			t.Fatalf("request %d: remaining %d, want %d", i+1, v.Remaining, 4-i)
		}
	}
	v, err := l.Take(ctx, r, "k")
	if err != nil || v.Allowed {
		t.Fatalf("sixth: %+v %v", v, err)
	}
	// One request refills every window/limit = 200ms.
	if v.RetryAfter <= 0 || v.RetryAfter > 200*time.Millisecond {
		t.Fatalf("retry after %v, want (0, 200ms]", v.RetryAfter)
	}
}

func TestRefillsSmoothly(t *testing.T) {
	l := limiter(t)
	r := rule(ratelimit.Rule{Name: "refill", Limit: 5, Window: 500 * time.Millisecond})
	ctx := context.Background()
	for range 5 {
		_, _ = l.Take(ctx, r, "k")
	}
	if v, _ := l.Take(ctx, r, "k"); v.Allowed {
		t.Fatal("allowed past the limit")
	}
	time.Sleep(130 * time.Millisecond) // one interval is 100ms
	if v, _ := l.Take(ctx, r, "k"); !v.Allowed {
		t.Fatal("no refill after one interval")
	}
	if v, _ := l.Take(ctx, r, "k"); v.Allowed {
		t.Fatal("refilled more than one")
	}
}

// Done criterion: a burst of failed sign-ins is throttled without affecting
// other users. Only failures spend, so the right password is never slowed.
func TestFailedSignInsThrottleOnlyThatAccount(t *testing.T) {
	l := limiter(t)
	r := rule(ratelimit.FailedSignIn)
	ctx := context.Background()

	for range r.Limit {
		if v, _ := l.Check(ctx, r, "account:attacked"); !v.Allowed {
			t.Fatal("refused before the limit")
		}
		_, _ = l.Penalize(ctx, r, "account:attacked")
	}
	if v, _ := l.Check(ctx, r, "account:attacked"); v.Allowed {
		t.Fatal("attacked account not throttled")
	}
	for range 50 {
		if v, _ := l.Check(ctx, r, "account:someone-else"); !v.Allowed {
			t.Fatal("another account was throttled")
		}
	}
	// Checking never spends: a successful sign-in costs nothing.
	for range 100 {
		_, _ = l.Check(ctx, r, "account:careful")
	}
	if v, _ := l.Check(ctx, r, "account:careful"); !v.Allowed || v.Remaining != r.Limit-1 {
		t.Fatalf("checks spent: %+v", v)
	}
}

// Done criterion: a client sending a hundred messages a second is throttled
// without the room noticing.
func TestMessageFloodIsThrottledPerMember(t *testing.T) {
	l := limiter(t)
	r := rule(ratelimit.MessageSend)
	ctx := context.Background()

	allowed := 0
	for range 100 {
		if v, _ := l.Take(ctx, r, "mbr:flooder"); v.Allowed {
			allowed++
		}
	}
	if allowed != r.Limit {
		t.Fatalf("flooder got %d of 100 through, want %d", allowed, r.Limit)
	}
	for i := range 5 {
		if v, _ := l.Take(ctx, r, "mbr:neighbour"); !v.Allowed {
			t.Fatalf("a neighbour's message %d was refused", i+1)
		}
	}
}

func TestOneLineRouteLimit(t *testing.T) {
	l := limiter(t)
	r := rule(ratelimit.Rule{Name: "route", Limit: 2, Window: time.Minute})

	mux := http.NewServeMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	limit := l.Routes(map[string]ratelimit.Bound{
		"GET /limited": ratelimit.On(r, ratelimit.ByMembership),
	})
	mux.Handle("GET /limited", limit(ok))
	mux.Handle("GET /open", limit(ok))

	send := func(path, membership string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(auth.WithCaller(req.Context(), auth.Caller{
			UserID: uuid.NewString(), OrgID: uuid.NewString(), MembershipID: membership,
		}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	a := uuid.NewString()
	for range 2 {
		if rec := send("/limited", a); rec.Code != http.StatusOK {
			t.Fatalf("within limit: %d", rec.Code)
		}
	}
	rec := send("/limited", a)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: %d", rec.Code)
	}
	if s, _ := strconv.Atoi(rec.Header().Get("Retry-After")); s < 1 {
		t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != "rate_limited" {
		t.Fatalf("envelope: %v", body)
	}
	if rec := send("/limited", uuid.NewString()); rec.Code != http.StatusOK {
		t.Fatalf("another member: %d", rec.Code)
	}
	for range 5 {
		if rec := send("/open", a); rec.Code != http.StatusOK {
			t.Fatalf("route without a rule: %d", rec.Code)
		}
	}
}

func TestInternalCallsBypass(t *testing.T) {
	l := limiter(t)
	r := rule(ratelimit.Rule{Name: "bypass", Limit: 1, Window: time.Minute})
	h := l.Wrap(ratelimit.On(r, ratelimit.ByIP), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(ratelimit.WithBypass(req.Context()))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("internal call %d: %d", i+1, rec.Code)
		}
	}
}

// With Redis unreachable, ordinary rules let traffic through and sign-in
// style rules refuse it.
func TestRedisDownFailsOpenOrClosedByRule(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	defer rdb.Close()
	l := ratelimit.New(rdb, quiet)
	ctx := context.Background()

	if v, err := l.Take(ctx, ratelimit.AuthenticatedRead, "k"); err != nil || !v.Allowed {
		t.Fatalf("fail-open rule: %+v %v", v, err)
	}
	if _, err := l.Take(ctx, ratelimit.FailedSignIn, "k"); !errors.Is(err, ratelimit.ErrUnavailable) {
		t.Fatalf("fail-closed rule: %v", err)
	}
}
