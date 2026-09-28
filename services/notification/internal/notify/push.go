package notify

import (
	"context"
	"errors"
	"time"
)

// Payload is what a push carries: small, and no message text unless the
// recipient allows previews.
type Payload struct {
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	Category Category  `json:"category"`
	Link     string    `json:"link"`
	Expires  time.Time `json:"expires_at,omitzero"`
	// A later push with the same key replaces the earlier on the device.
	Collapse string `json:"collapse,omitempty"`
}

// TTL is how long the vendor may hold the push: until it stops mattering,
// or four weeks.
func (p Payload) TTL(now time.Time) time.Duration {
	if p.Expires.IsZero() {
		return 28 * 24 * time.Hour
	}
	return p.Expires.Sub(now)
}

// Vendor errors, classified as the push story asks.
var (
	// ErrInvalidToken: the device is gone; delete it.
	ErrInvalidToken = errors.New("push: invalid token")
	// ErrRateLimited: back off; the push is dropped and counted.
	ErrRateLimited = errors.New("push: rate limited")
	// ErrTransient: worth one retry.
	ErrTransient = errors.New("push: transient")
)

// Pusher delivers to one platform's devices.
type Pusher interface {
	Push(ctx context.Context, token string, p Payload) error
}

// Pushers is a pusher per platform; a platform with none gets nothing.
type Pushers map[string]Pusher
