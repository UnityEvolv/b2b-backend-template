// Package hostevents pushes changes into running offices: the one way in to
// the realtime core from outside its sockets.
//
// A Redis pub/sub channel the realtime service listens on, bound to the
// engine's event bus. There is no broker between them, and nothing is
// queued: an event nobody is listening for is about an office nobody is in,
// and the next person to enter is checked at the door anyway.
package hostevents

import (
	"context"
	"encoding/json"

	"github.com/redis/go-redis/v9"
)

// Channel is the Redis pub/sub channel. The realtime service names the same.
const Channel = "unityofis:host-events"

// The event types the realtime service understands.
const (
	// TypeAccessChanged: may this person, or everyone in an office, still be
	// where they are? The engine asks its identity adapter again, the same
	// questions it asks at the door, and moves or disconnects whoever the
	// answer changed for.
	TypeAccessChanged = "access.changed"
	// TypeTemplateChanged: an office's layout changed. Clients re-read it,
	// and anybody in a room it no longer has moves to the break room.
	TypeTemplateChanged = "template.changed"
	// TypeStatusExternal: a status the office cannot work out, such as a
	// calendar meeting (UO-187). Status is "in_meeting", or empty to clear;
	// Quiet makes it silence knocks the way do not disturb does.
	TypeStatusExternal = "status.external"
)

// Event is one push. Which fields matter depends on the type; an empty
// user means everyone in the office.
type Event struct {
	Type     string `json:"type"`
	OrgID    string `json:"org_id,omitempty"`
	OfficeID string `json:"office_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	// The sentence shown to whoever the change moves or disconnects.
	Message string `json:"message,omitempty"`
	// For TypeStatusExternal.
	Status string `json:"status,omitempty"`
	Quiet  bool   `json:"quiet,omitempty"`
}

// Publisher pushes events to the realtime service.
type Publisher interface {
	Publish(ctx context.Context, ev Event) error
}

// Redis publishes over Redis pub/sub.
type Redis struct{ Client *redis.Client }

// Publish is the event, as JSON, on Channel.
func (p Redis) Publish(ctx context.Context, ev Event) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return p.Client.Publish(ctx, Channel, raw).Err()
}

// Discard publishes nothing: a service with no Redis, and tests.
type Discard struct{}

// Publish does nothing.
func (Discard) Publish(context.Context, Event) error { return nil }
