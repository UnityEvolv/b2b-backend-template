package livebus_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
)

// Who an event is for: the session it names, else the person (in the org
// it names), else everyone in the org.
func TestConcerns(t *testing.T) {
	session, user, org := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, c := range []struct {
		ev   livebus.Event
		want bool
	}{
		{livebus.Event{Type: livebus.SessionRevoked, SessionID: session, UserID: user}, true},
		{livebus.Event{Type: livebus.SessionRevoked, SessionID: uuid.NewString(), UserID: user}, false},
		{livebus.Event{Type: livebus.MembershipChanged, UserID: user, OrgID: org}, true},
		{livebus.Event{Type: livebus.MembershipChanged, UserID: user, OrgID: uuid.NewString()}, false},
		{livebus.Event{Type: livebus.MembershipChanged, UserID: uuid.NewString(), OrgID: org}, false},
		{livebus.Event{Type: livebus.OrgSuspended, OrgID: org}, true},
		{livebus.Event{Type: livebus.OrgSuspended, OrgID: uuid.NewString()}, false},
		{livebus.Event{Type: "project.shared"}, false},
	} {
		if got := c.ev.Concerns(session, user, org); got != c.want {
			t.Errorf("%+v: %v", c.ev, got)
		}
	}
}

// Over Redis, under the prefix: every subscriber hears every event
// published after it subscribed; a product's own type once registered; a
// type nobody registered is refused.
func TestBus(t *testing.T) {
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
	names := config.Redis{Prefix: "test-" + uuid.NewString()}
	types := livebus.New()
	bus := livebus.NewBus(rdb, names.LiveEvents(), types, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(ctx, livebus.Event{Type: "project.shared"}); !errors.Is(err, livebus.ErrUnknownType) {
		t.Errorf("an unregistered type: %v", err)
	}
	types.Register("project.shared", "A project was shared with someone.")
	session := uuid.NewString()
	for _, ev := range []livebus.Event{
		{Type: livebus.SessionRevoked, SessionID: session, Scope: livebus.ScopeSession, Code: "revoked"},
		{Type: "project.shared", UserID: uuid.NewString(), Data: map[string]any{"project_id": "p1"}},
	} {
		if err := bus.Publish(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for _, ch := range []<-chan livebus.Event{a, b} {
		for _, want := range []livebus.Type{livebus.SessionRevoked, "project.shared"} {
			select {
			case ev := <-ch:
				if ev.Type != want || ev.At.IsZero() {
					t.Errorf("got %+v, want %s", ev, want)
				}
				if want == livebus.SessionRevoked && ev.SessionID != session {
					t.Errorf("session %q", ev.SessionID)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no %s", want)
			}
		}
	}
	// Under the configured prefix, nowhere else.
	if names.LiveEvents() != names.Prefix+":live-events" {
		t.Errorf("channel %q", names.LiveEvents())
	}
	cancel()
	if _, ok := <-a; ok {
		t.Error("a subscription outlived its context")
	}
}

// A type that is not dotted lower case cannot be registered.
func TestRegisterRefusesABadName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registered")
		}
	}()
	livebus.New().Register("Project Shared", "")
}
