package server

import (
	"context"
	"encoding/json"

	"github.com/redis/go-redis/v9"
)

// Host events go out on config.Redis.HostEvents: things pushed into a
// running client from outside it. There is no broker between them.

// AccessRevoked is the one event this service publishes: a person's access
// in an org has ended right now, and any socket they have open there must
// be told and closed rather than left working until its token expires.
type AccessRevoked struct {
	Type string `json:"type"` // always "access.revoked"
	// Whose access, and where. A listener matches the user; the org narrows
	// it to their connections in that org.
	UserID    string `json:"user_id"`
	OrgID     string `json:"org_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	// Scope says how far it reaches: one session's sockets (signed out on
	// one device, the others stay), or every socket the person has open
	// (their access in the org ended).
	Scope string `json:"scope"`
	// A stable code the client shows a message for, and a sentence for
	// anything that cannot look one up.
	Code    string `json:"code"`
	Message string `json:"message"`
}

// The scopes of a revocation.
const (
	scopeSession = "session"
	scopeUser    = "user"
)

// Publisher pushes host events to the realtime service.
type Publisher interface {
	Publish(ctx context.Context, ev AccessRevoked) error
}

// RedisPublisher publishes over Redis pub/sub, on Channel.
type RedisPublisher struct {
	Client  *redis.Client
	Channel string
}

// Publish is the event, as JSON, on the host events channel.
func (p RedisPublisher) Publish(ctx context.Context, ev AccessRevoked) error {
	ev.Type = "access.revoked"
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return p.Client.Publish(ctx, p.Channel, raw).Err()
}

// The reasons a session ends, as stable codes. The client keeps the words.
const (
	reasonSignedOut         = "signed_out"
	reasonRevoked           = "revoked"            // by the person, from their sessions list
	reasonRevokedEverywhere = "revoked_everywhere" // sign out everywhere else
	reasonIdle              = "idle"
	reasonNoMembership      = "no_membership" // their last org ended
	// UO-183, UO-184.
	reasonAccountDeleted    = "account_deleted"
	reasonOrgClosing        = "organization_closing"
	reasonEmailChangeUndone = "email_change_undone"
)

// message is what a person sees when a socket is closed for a reason.
func message(reason string) string {
	switch reason {
	case "deactivated":
		return "Your account in this organization has been deactivated."
	case "suspended":
		return "Your account in this organization has been suspended."
	case "left":
		return "You have left this organization."
	case reasonRevoked, reasonRevokedEverywhere:
		return "This session was signed out from another device."
	case "revoked_by_admin":
		return "An administrator of your organization signed you out."
	case reasonNoMembership:
		return "You no longer belong to any organization."
	case "password_changed":
		return "Your password was changed. Sign in again."
	case "mfa_reset":
		return "Your two-factor sign-in was reset. Sign in again."
	case reasonAccountDeleted:
		return "Your account has been deleted."
	case reasonOrgClosing:
		return "This organization is closing. An Owner can reopen it from the link in the email sent when it closed."
	case reasonEmailChangeUndone:
		return "A change to your sign-in email was undone. Sign in again."
	}
	return "Your session has ended. Sign in again."
}
