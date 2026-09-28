package notify

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/hostevents"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Channel is the Redis channel services emit events on. Every node of this
// service hears every event; the dedupe key makes each one notification.
const Channel = "unityofis:notify"

// Listen takes events from Redis until ctx ends: notifications on Channel,
// and ended sessions on the host events channel, whose devices stop getting
// pushes at once.
func (r *Router) Listen(ctx context.Context, client *redis.Client) {
	sub := client.Subscribe(ctx, Channel, hostevents.Channel)
	defer sub.Close()
	messages := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-messages:
			if !ok {
				return
			}
			switch m.Channel {
			case Channel:
				var ev Event
				if err := json.Unmarshal([]byte(m.Payload), &ev); err != nil {
					r.logger.Warn("notification event ignored", "code", "malformed")
					continue
				}
				if err := r.Handle(ctx, ev); err != nil {
					r.logger.Warn("notification event not handled", "kind", ev.Kind, "org_id", ev.OrgID, "error", err)
				}
			case hostevents.Channel:
				r.revoked(ctx, m.Payload)
			}
		}
	}
}

// revoked removes the devices of a session, or of every session of a
// person, when the identity service ends them.
func (r *Router) revoked(ctx context.Context, payload string) {
	var ev struct {
		Type      string `json:"type"`
		UserID    string `json:"user_id"`
		SessionID string `json:"session_id"`
		Scope     string `json:"scope"`
	}
	if json.Unmarshal([]byte(payload), &ev) != nil || ev.Type != "access.revoked" {
		return
	}
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	err := r.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if ev.Scope == "session" && ev.SessionID != "" {
			_, err := q.DeleteSessionDevicesEverywhere(ctx, ev.SessionID)
			return err
		}
		if ev.UserID != "" {
			_, err := q.DeleteUserDevicesEverywhere(ctx, ev.UserID)
			return err
		}
		return nil
	})
	if err != nil {
		r.logger.Warn("devices of an ended session not removed", "error", err)
	}
}
