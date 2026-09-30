// Package livebus is the live-session event bus (UO-77): what a service
// pushes to the people who have the product open right now, such as a
// session that has just ended. One Redis pub/sub channel under the
// configurable prefix (config.Redis.LiveEvents); no broker and nothing
// queued, because every event is about what is open now, and whatever opens
// next is checked at the door anyway.
//
// The core's events are typed here: session.revoked, membership.changed and
// org.suspended. A product registers its own types (Default.Register) in
// the process that publishes them; listeners pass on whatever reaches them.
// The identity service's SSE endpoint, GET /identity/v1/session/events, is
// the reference listener: it streams to one open browser session the
// events that concern it.
package livebus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Type is what an event says happened: dotted, lower case.
type Type string

// The core's event types.
const (
	// SessionRevoked: a session ended now. With SessionID, that session
	// (signed out on one device); with only UserID, every session of the
	// person. Code says why, Message says it in a sentence.
	SessionRevoked Type = "session.revoked"
	// MembershipChanged: a membership's role or status changed, or the
	// session holding it moved to another org. The app reads its grant and
	// the session again.
	MembershipChanged Type = "membership.changed"
	// OrgSuspended: the org can no longer be used, such as while it is
	// closing. Everyone in it is signed out of it.
	OrgSuspended Type = "org.suspended"
)

// Scope of a SessionRevoked.
const (
	// ScopeSession is one session: its sockets and tabs close, the
	// person's other devices stay.
	ScopeSession = "session"
	// ScopeUser is every session the person has open in the org.
	ScopeUser = "user"
)

// Event is one push. Who it concerns is the most specific id it carries: a
// session, else a person (in an org, when OrgID is set too), else everyone
// in an org.
type Event struct {
	Type         Type   `json:"type"`
	OrgID        string `json:"org_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	MembershipID string `json:"membership_id,omitempty"`
	// Scope is how far a SessionRevoked reaches: ScopeSession or ScopeUser.
	Scope string `json:"scope,omitempty"`
	// Code is a stable reason the client keys its words on; Message is a
	// sentence for anything that cannot.
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	// Data is a product event's own payload. Ids only, never a name or an
	// email: the bus is not for personal data.
	Data map[string]any `json:"data,omitempty"`
	At   time.Time      `json:"at"`
}

// Concerns reports whether ev is for an open session: the session itself,
// its person, or its org. user and org are the session's person and the org
// it is active in.
func (ev Event) Concerns(session, user, org string) bool {
	switch {
	case ev.SessionID != "":
		return ev.SessionID == session
	case ev.UserID != "":
		return ev.UserID == user && (ev.OrgID == "" || ev.OrgID == org)
	case ev.OrgID != "":
		return ev.OrgID == org
	}
	return false
}

var typeName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Registry is the event types that may be published: the core's and the
// ones a product registers. Safe for concurrent use.
type Registry struct {
	mu    sync.RWMutex
	types map[Type]string
}

// New is a registry with the core's types.
func New() *Registry {
	r := &Registry{types: map[Type]string{}}
	r.Register(SessionRevoked, "A session ended.")
	r.Register(MembershipChanged, "A membership's role or status changed, or a session moved off it.")
	r.Register(OrgSuspended, "The organization can no longer be used.")
	return r
}

// Default is the registry Publish checks against in this process. A product
// registers its types at start.
var Default = New()

// Register adds a type a product publishes ("project.shared"), with what it
// means. A name that is not dotted lower case panics: it is a programming
// error at start, not a request.
func (r *Registry) Register(t Type, description string) {
	if !typeName.MatchString(string(t)) {
		panic(fmt.Sprintf("livebus: %q cannot be an event type", t))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.types[t] = description
}

// Known reports whether t is registered.
func (r *Registry) Known(t Type) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.types[t]
	return ok
}

// ErrUnknownType is an event of a type nobody registered.
var ErrUnknownType = errors.New("livebus: the event type is not registered")

// Publisher pushes events onto the bus.
type Publisher interface {
	Publish(ctx context.Context, ev Event) error
}

// Discard publishes nothing: a service with no Redis, and tests.
type Discard struct{}

// Publish does nothing.
func (Discard) Publish(context.Context, Event) error { return nil }

// Bus is the bus over Redis pub/sub on one channel. One Redis subscription
// per process, shared by every local subscriber, however many browsers are
// connected.
type Bus struct {
	client  *redis.Client
	channel string
	types   *Registry
	logger  *slog.Logger

	mu      sync.Mutex
	subs    map[chan Event]struct{}
	started bool
	ready   chan error
}

// NewBus is the bus on channel (config.Redis.LiveEvents), checking
// published types against types (nil is Default).
func NewBus(client *redis.Client, channel string, types *Registry, logger *slog.Logger) *Bus {
	if types == nil {
		types = Default
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Bus{client: client, channel: channel, types: types, logger: logger, subs: map[chan Event]struct{}{}}
}

// Publish is ev, stamped now, as JSON on the channel. A type nobody
// registered is refused.
func (b *Bus) Publish(ctx context.Context, ev Event) error {
	if !b.types.Known(ev.Type) {
		return fmt.Errorf("%w: %q", ErrUnknownType, ev.Type)
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return b.client.Publish(ctx, b.channel, raw).Err()
}

// buffer is how many events a slow subscriber may fall behind by before
// the next is dropped for it.
const buffer = 64

// Subscribe is every event on the bus from now until ctx ends, when the
// channel closes. It returns once the Redis subscription is in place, so
// nothing published after it returns is missed.
func (b *Bus) Subscribe(ctx context.Context) (<-chan Event, error) {
	if err := b.start(ctx); err != nil {
		return nil, err
	}
	ch := make(chan Event, buffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
		close(ch)
	}()
	return ch, nil
}

// start runs the one Redis subscription, once, and waits for Redis to
// confirm it.
func (b *Bus) start(ctx context.Context) error {
	b.mu.Lock()
	if !b.started {
		b.started = true
		b.ready = make(chan error, 1)
		go b.listen()
	}
	ready := b.ready
	b.mu.Unlock()
	select {
	case err := <-ready:
		// Put it back for the next caller to read too.
		ready <- err
		if err != nil {
			b.mu.Lock()
			b.started = false
			b.mu.Unlock()
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Bus) listen() {
	ctx := context.Background()
	sub := b.client.Subscribe(ctx, b.channel)
	if _, err := sub.Receive(ctx); err != nil {
		_ = sub.Close()
		b.ready <- err
		return
	}
	b.ready <- nil
	defer sub.Close()
	for m := range sub.Channel() {
		var ev Event
		if err := json.Unmarshal([]byte(m.Payload), &ev); err != nil || ev.Type == "" {
			b.logger.Warn("live event ignored", "code", "malformed")
			continue
		}
		b.mu.Lock()
		for ch := range b.subs {
			select {
			case ch <- ev:
			default:
				b.logger.Warn("live event dropped for a slow subscriber", "type", ev.Type)
			}
		}
		b.mu.Unlock()
	}
}
