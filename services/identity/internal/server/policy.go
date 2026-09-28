package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// The platform's session policy: what an org gets until it sets its own,
// and the range it may set. The range is the platform's, not configurable,
// so no org can make a session last forever or end before it started.
const (
	DefaultLifetime = 90 * 24 * time.Hour
	DefaultIdle     = 14 * 24 * time.Hour
	MinLifetime     = 24 * time.Hour
	MaxLifetime     = 365 * 24 * time.Hour
	MinIdle         = 15 * time.Minute
	MaxIdle         = 90 * 24 * time.Hour
)

// policy is how long an org's sessions last.
type policy struct {
	Lifetime time.Duration
	Idle     time.Duration
	// MFARequired: local accounts need a second factor to sign in here.
	MFARequired bool
	Configured  bool
}

var platformPolicy = policy{Lifetime: DefaultLifetime, Idle: DefaultIdle}

// policyFor is the org's policy, or the platform's when it has none. The
// platform org itself always demands a second factor (UO-82): its members
// can see every organization, so nobody can configure that away.
func (s *Server) policyFor(ctx context.Context, org uuid.UUID) (policy, error) {
	p, err := s.storedPolicy(ctx, org)
	if err == nil && strings.EqualFold(org.String(), auth.PlatformOrg) {
		p.MFARequired = true
	}
	return p, err
}

func (s *Server) storedPolicy(ctx context.Context, org uuid.UUID) (policy, error) {
	var row store.SessionPolicy
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetSessionPolicy(ctx, org)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return platformPolicy, nil
	}
	if err != nil {
		return policy{}, err
	}
	return fromRow(row), nil
}

func fromRow(row store.SessionPolicy) policy {
	return policy{Lifetime: time.Duration(row.LifetimeSeconds) * time.Second, Idle: time.Duration(row.IdleTimeoutSeconds) * time.Second, MFARequired: row.MfaRequired, Configured: true}
}

func toPolicy(org uuid.UUID, p policy) api.SessionPolicy {
	out := api.SessionPolicy{OrgId: org, LifetimeSeconds: int(p.Lifetime.Seconds()), IdleTimeoutSeconds: int(p.Idle.Seconds()), MfaRequired: p.MFARequired, Configured: p.Configured}
	out.Limits.MinLifetimeSeconds = int(MinLifetime.Seconds())
	out.Limits.MaxLifetimeSeconds = int(MaxLifetime.Seconds())
	out.Limits.MinIdleTimeoutSeconds = int(MinIdle.Seconds())
	out.Limits.MaxIdleTimeoutSeconds = int(MaxIdle.Seconds())
	return out
}

// GetSessionPolicy is the org's policy, for anyone in the org or an operator.
func (s *Server) GetSessionPolicy(ctx context.Context, req api.GetSessionPolicyRequestObject) (api.GetSessionPolicyResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil {
		return api.GetSessionPolicy403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	p, err := s.policyFor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetSessionPolicy200JSONResponse(toPolicy(req.OrgId, p)), nil
}

// SetSessionPolicy changes it, within the platform's range, for sessions
// started from now on. The settings permission. Audited.
func (s *Server) SetSessionPolicy(ctx context.Context, req api.SetSessionPolicyRequestObject) (api.SetSessionPolicyResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		return api.SetSessionPolicy403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to change the organization's settings."}, nil
	}
	lifetime := time.Duration(req.Body.LifetimeSeconds) * time.Second
	idle := time.Duration(req.Body.IdleTimeoutSeconds) * time.Second
	fields := map[string]string{}
	if lifetime < MinLifetime || lifetime > MaxLifetime {
		fields["lifetime_seconds"] = "between one day and one year"
	}
	if idle < MinIdle || idle > MaxIdle {
		fields["idle_timeout_seconds"] = "between fifteen minutes and ninety days"
	}
	if len(fields) == 0 && idle > lifetime {
		fields["idle_timeout_seconds"] = "not longer than the lifetime"
	}
	if len(fields) > 0 {
		return api.SetSessionPolicy400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The session policy is out of the platform's range.", Fields: &fields}}, nil
	}
	before, err := s.policyFor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	mfaRequired := before.MFARequired
	if req.Body.MfaRequired != nil {
		mfaRequired = *req.Body.MfaRequired
	}
	var row store.SessionPolicy
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).UpsertSessionPolicy(ctx, store.UpsertSessionPolicyParams{OrgID: req.OrgId, LifetimeSeconds: int32(lifetime.Seconds()), IdleTimeoutSeconds: int32(idle.Seconds()), MfaRequired: mfaRequired})
		return err
	})
	if err != nil {
		return nil, err
	}
	after := fromRow(row)
	if before != after {
		err := s.recorder.Record(ctx, audit.Event{
			OrgID: req.OrgId.String(), Action: "session.policy_changed", TargetType: "organization", TargetID: req.OrgId.String(),
			Details: map[string]any{
				"lifetime_seconds": int(after.Lifetime.Seconds()), "idle_timeout_seconds": int(after.Idle.Seconds()), "mfa_required": after.MFARequired,
				"previous_lifetime_seconds": int(before.Lifetime.Seconds()), "previous_idle_timeout_seconds": int(before.Idle.Seconds()), "previous_mfa_required": before.MFARequired,
			},
		})
		if err != nil {
			return nil, err
		}
	}
	return api.SetSessionPolicy200JSONResponse(toPolicy(req.OrgId, after)), nil
}
