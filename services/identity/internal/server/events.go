package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
)

// Every revocation is pushed on the live-session bus (pkg/livebus) as
// session.revoked, and a session moved off a membership that ended as
// membership.changed: an open app is told at once rather than left working
// until its access token expires. GET /v1/session/events streams them to
// the browser.

// The scopes of a revocation.
const (
	scopeSession = livebus.ScopeSession
	scopeUser    = livebus.ScopeUser
)

// Subscriber is the bus's listening end, for the stream.
type Subscriber interface {
	Subscribe(ctx context.Context) (<-chan livebus.Event, error)
}

// WithLive is s streaming the bus to open sessions at GET /v1/session/events.
func (s *Server) WithLive(sub Subscriber) *Server {
	s.live = sub
	return s
}

// heartbeat is how often an idle stream says it is still there, so proxies
// keep it open and a dead connection is noticed.
var heartbeat = 25 * time.Second

// SessionEvents is GET /v1/session/events: a Server-Sent Events stream of
// the live-session events that concern the browser's session, named by its
// session cookie as the refresh is. It opens with a "ready" event, carries
// each event as
//
//	event: session.revoked
//	data: {"type":"session.revoked","user_id":"…","session_id":"…","scope":"session","code":"revoked","message":"…","at":"…"}
//
// and ends after a session.revoked for this session, which the app answers
// by signing out. A session that is already over gets that event at once.
// The browser opens it with new EventSource(url, {withCredentials: true}).
func (s *Server) SessionEvents() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.live == nil {
			httpx.WriteError(w, http.StatusNotImplemented, "session.events_unavailable", "Live events are not available here.")
			return
		}
		c := &cookies{in: map[string]string{}, names: s.cfg.Cookies}
		for _, cookie := range r.Cookies() {
			c.in[cookie.Name] = cookie.Value
		}
		ctx := context.WithValue(r.Context(), cookiesKey{}, c)
		session, live, err := s.currentSession(ctx)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Something went wrong.")
			return
		}
		if !live && c.in[c.name(sessionCookie)] == "" {
			httpx.WriteError(w, http.StatusUnauthorized, codeNoSession, "Not signed in.")
			return
		}
		var events <-chan livebus.Event
		if live {
			// Subscribed before the first byte, so nothing published after
			// the browser sees "ready" is missed.
			if events, err = s.live.Subscribe(r.Context()); err != nil {
				s.logger.Error("live events unavailable", "error", err)
				httpx.WriteError(w, http.StatusServiceUnavailable, "session.events_unavailable", "Live events are not available right now.")
				return
			}
		}
		// A stream outlives the server's write timeout; each write is
		// flushed as it goes.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{})
		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		if !live {
			// Over already: say so, and end.
			writeEvent(w, livebus.Event{Type: livebus.SessionRevoked, Scope: scopeSession, Code: reasonSignedOut, Message: message(""), At: time.Now().UTC()})
			_ = rc.Flush()
			return
		}
		id, user, org := session.ID.String(), session.UserID.String(), ""
		if session.ActiveOrgID.Valid {
			org = uuid.UUID(session.ActiveOrgID.Bytes).String()
		}
		fmt.Fprintf(w, "event: ready\ndata: {\"session_id\":%q}\n\n", id)
		_ = rc.Flush()
		tick := time.NewTicker(heartbeat)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				fmt.Fprint(w, ": still here\n\n")
				_ = rc.Flush()
			case ev, ok := <-events:
				if !ok {
					return
				}
				if !ev.Concerns(id, user, org) {
					continue
				}
				writeEvent(w, ev)
				_ = rc.Flush()
				if ev.Type == livebus.SessionRevoked && (ev.SessionID == id || ev.SessionID == "") {
					return
				}
			}
		}
	})
}

// writeEvent is one event in the stream, named by its type.
func writeEvent(w http.ResponseWriter, ev livebus.Event) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, raw)
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
