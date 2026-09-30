package server

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Notice is an event for the notification service, to named memberships.
// It is what the notification service's intake reads on the notify
// channel; the router fills in who did it from Actor, and words it from the
// category's copy for Kind.
type Notice struct {
	ID         string         `json:"id"`
	OrgID      string         `json:"org_id"`
	Kind       string         `json:"kind"`
	Category   string         `json:"category"`
	Recipients []uuid.UUID    `json:"recipients"`
	Actor      *uuid.UUID     `json:"actor,omitempty"`
	Link       string         `json:"link"`
	Data       map[string]any `json:"data,omitempty"`
}

// Notifier hands notices to the notification service.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// RedisNotifier publishes on the notification service's channel,
// config.Redis.Notify.
type RedisNotifier struct {
	Client  *redis.Client
	Channel string
}

// Notify publishes n.
func (r RedisNotifier) Notify(ctx context.Context, n Notice) error {
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return r.Client.Publish(ctx, r.Channel, raw).Err()
}

// WithNotifier is s telling people about their own security and
// membership: a sign-in from a new device, a change to their second factor,
// an invitation to another org.
func (s *Server) WithNotifier(n Notifier) *Server {
	s.notices = n
	return s
}

// The kinds of notice this service sends, each worded by its category.
const (
	kindNewSignIn  = "new_sign_in"
	kindMfaChanged = "mfa_changed"
	kindInvited    = "invited"
)

// The second-factor changes a person is told about, as mfa_changed's
// data.change.
const (
	mfaEnrolled      = "enrolled"
	mfaRemoved       = "removed"
	mfaReset         = "reset"
	mfaRecoveryCodes = "recovery_codes"
)

// notify hands n on. Best effort: what it tells of has happened either way.
// Only ids are logged, never the person.
func (s *Server) notify(ctx context.Context, n Notice) {
	if s.notices == nil || len(n.Recipients) == 0 {
		return
	}
	if err := s.notices.Notify(ctx, n); err != nil {
		s.logger.Warn("notice not sent", "kind", n.Kind, "org_id", n.OrgID, "error", err)
	}
}

// memberIn is the person's active membership to tell them through: the one
// in org, or else their first active one anywhere. False when they have
// none, or it cannot be found out.
func (s *Server) memberIn(ctx context.Context, userID, org uuid.UUID) (orgID, membershipID uuid.UUID, ok bool) {
	all, err := s.users.ListMemberships(ctx, userID)
	if err != nil {
		s.logger.Warn("notice recipient not found", "user_id", userID, "error", err)
		return uuid.Nil, uuid.Nil, false
	}
	var first *Membership
	for i := range all {
		if all[i].Status != "active" {
			continue
		}
		if all[i].OrgID == org {
			return all[i].OrgID, all[i].ID, true
		}
		if first == nil {
			first = &all[i]
		}
	}
	if first == nil {
		return uuid.Nil, uuid.Nil, false
	}
	return first.OrgID, first.ID, true
}

// newDevice is whether a session about to start for the person is from a
// device they have not signed in from before: they have signed in before,
// and never with this user agent. A first sign-in is nobody's news.
func (s *Server) newDevice(ctx context.Context, userID uuid.UUID, ua string) (bool, error) {
	var earlier []store.Session
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		earlier, err = store.New(tx).ListSessionsOfUser(ctx, userID)
		return err
	})
	if err != nil || len(earlier) == 0 {
		return false, err
	}
	for _, e := range earlier {
		if e.UserAgent.String == ua {
			return false, nil
		}
	}
	return true, nil
}

// signedInFromNewDevice tells the person about a sign-in from a device they
// have not used before, through the membership they landed in, or their
// membership in the org that signed them in.
func (s *Server) signedInFromNewDevice(ctx context.Context, session store.Session, land *membership) {
	if s.notices == nil {
		return
	}
	org, to := session.SignedInOrgID, uuid.Nil
	if land != nil {
		org, to = land.OrgID, land.MembershipID
	} else {
		var ok bool
		if org, to, ok = s.memberIn(ctx, session.UserID, session.SignedInOrgID); !ok {
			return
		}
	}
	s.notify(ctx, Notice{
		ID: "security:" + kindNewSignIn + ":" + session.ID.String(), OrgID: org.String(), Kind: kindNewSignIn,
		Category: notifycat.Security, Recipients: []uuid.UUID{to}, Link: "/settings/security",
	})
}

// mfaChanged tells the person their second factor changed. by is the
// admin's membership when it was not the person themselves, and names them
// in the notice.
func (s *Server) mfaChanged(ctx context.Context, userID, org, membershipID uuid.UUID, change string, by *uuid.UUID) {
	if s.notices == nil {
		return
	}
	if membershipID == uuid.Nil {
		var ok bool
		if org, membershipID, ok = s.memberIn(ctx, userID, org); !ok {
			return
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return
	}
	s.notify(ctx, Notice{
		ID: "security:" + kindMfaChanged + ":" + id.String(), OrgID: org.String(), Kind: kindMfaChanged,
		Category: notifycat.Security, Recipients: []uuid.UUID{membershipID}, Actor: by, Link: "/settings/security",
		Data: map[string]any{"change": change},
	})
}

// invited tells someone who already has an account that another org has
// invited them, in the app they already use, beside the email. The link
// is not in the notice: the invite's token is in the email only.
func (s *Server) invited(ctx context.Context, row store.Invite) {
	if s.notices == nil {
		return
	}
	userID, err := s.users.FindByEmail(ctx, row.Email)
	if err != nil {
		return // nobody yet: the email is the whole invitation
	}
	org, to, ok := s.memberIn(ctx, userID, uuid.Nil)
	if !ok || org == row.OrgID {
		return
	}
	data := map[string]any{"role": row.Role}
	if name, err := s.orgName(ctx, row.OrgID); err == nil && name != "" {
		data["where"] = name
	}
	s.notify(ctx, Notice{
		ID: "membership:" + kindInvited + ":" + row.ID.String() + ":" + row.ExpiresAt.UTC().Format("20060102T150405"), OrgID: org.String(), Kind: kindInvited,
		Category: notifycat.Membership, Recipients: []uuid.UUID{to}, Link: "/", Data: data,
	})
}

// callerMembership is the signed-in person's membership when their token
// is for org, so a change they make is told to them there; uuid.Nil
// otherwise, and the notice finds one.
func callerMembership(ctx context.Context, org uuid.UUID) uuid.UUID {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.OrgID != org.String() {
		return uuid.Nil
	}
	id, err := uuid.Parse(c.MembershipID)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// activeIn is the active membership in org among all, or uuid.Nil.
func activeIn(all []Membership, org uuid.UUID) uuid.UUID {
	for _, m := range all {
		if m.OrgID == org && m.Status == "active" {
			return m.ID
		}
	}
	return uuid.Nil
}
