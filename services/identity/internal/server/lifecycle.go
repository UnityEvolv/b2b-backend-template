package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Org offboarding and account deletion (UO-183, UO-184): this service's
// share of an org's export and purge, of a person's export, and of deleting
// a person. Only the organization service asks for data; the user service
// and the organization service delete people.

const serviceName = "identity"

// part is an orgdata part as the API answers it.
func part(v any, files []orgdata.File) (api.DataPart, error) {
	p, err := orgdata.Marshal(serviceName, v, files)
	if err != nil {
		return api.DataPart{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return api.DataPart{}, err
	}
	var out api.DataPart
	err = json.Unmarshal(raw, &out)
	return out, err
}

func timeOf(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

func uuidOf(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	v := uuid.UUID(u.Bytes)
	return &v
}

func textOf(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

type exportedProvider struct {
	Type         string     `json:"type"`
	TenantID     string     `json:"tenant_id"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret"`
	Issuer       string     `json:"issuer"`
	Status       string     `json:"status"`
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type exportedPolicy struct {
	LifetimeSeconds    int32 `json:"lifetime_seconds"`
	IdleTimeoutSeconds int32 `json:"idle_timeout_seconds"`
	MFARequired        bool  `json:"mfa_required"`
}

type exportedInvite struct {
	ID                    uuid.UUID  `json:"id"`
	Email                 string     `json:"email"`
	Kind                  string     `json:"kind"`
	Role                  string     `json:"role"`
	RoomID                *uuid.UUID `json:"room_id,omitempty"`
	Purpose               *string    `json:"purpose,omitempty"`
	App                   string     `json:"app"`
	ExpiresAt             time.Time  `json:"expires_at"`
	AcceptedAt            *time.Time `json:"accepted_at,omitempty"`
	AcceptedUserID        *uuid.UUID `json:"accepted_user_id,omitempty"`
	AcceptedMembershipID  *uuid.UUID `json:"accepted_membership_id,omitempty"`
	RevokedAt             *time.Time `json:"revoked_at,omitempty"`
	InvitedByMembershipID *uuid.UUID `json:"invited_by_membership_id,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
}

// ExportOrgData is the org's identity provider without its secret, its
// session policy, and its invites without their tokens.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}}, nil
	}
	out := struct {
		IdentityProvider *exportedProvider `json:"identity_provider"`
		SessionPolicy    *exportedPolicy   `json:"session_policy"`
		Invites          []exportedInvite  `json:"invites"`
		Note             string            `json:"note"`
	}{Invites: []exportedInvite{}, Note: "Secrets are not exported: the identity provider's client secret and the invite links are left out."}
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		idp, err := q.GetIdentityProvider(ctx, req.OrgId)
		switch {
		case err == nil:
			out.IdentityProvider = &exportedProvider{
				Type: idp.Type, TenantID: idp.TenantID, ClientID: idp.ClientID, ClientSecret: "not exported",
				Issuer: idp.Issuer, Status: idp.Status, VerifiedAt: timeOf(idp.VerifiedAt), CreatedAt: idp.CreatedAt.UTC(),
			}
		case err != pgx.ErrNoRows:
			return err
		}
		policy, err := q.GetSessionPolicy(ctx, req.OrgId)
		switch {
		case err == nil:
			out.SessionPolicy = &exportedPolicy{LifetimeSeconds: policy.LifetimeSeconds, IdleTimeoutSeconds: policy.IdleTimeoutSeconds, MFARequired: policy.MfaRequired}
		case err != pgx.ErrNoRows:
			return err
		}
		invites, err := q.ListInvitesOfOrg(ctx, req.OrgId)
		if err != nil {
			return err
		}
		for _, inv := range invites {
			out.Invites = append(out.Invites, exportedInvite{
				ID: inv.ID, Email: inv.Email, Kind: inv.Kind, Role: inv.Role, RoomID: uuidOf(inv.RoomID), Purpose: textOf(inv.Purpose),
				App: inv.App, ExpiresAt: inv.ExpiresAt.UTC(), AcceptedAt: timeOf(inv.AcceptedAt), AcceptedUserID: uuidOf(inv.AcceptedUserID),
				AcceptedMembershipID: uuidOf(inv.AcceptedMembershipID), RevokedAt: timeOf(inv.RevokedAt),
				InvitedByMembershipID: uuidOf(inv.InvitedByMembershipID), CreatedAt: inv.CreatedAt.UTC(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p, err := part(out, nil)
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(p), nil
}

// PurgeOrgData deletes everything this service keeps for an org: its
// provider, policy, sign-ins in flight, invites, links sent on its behalf,
// and the sessions working in it or signed in by it. Then counts what is
// left. Idempotent.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}}, nil
	}
	org := req.OrgId
	var remaining int64
	err := s.cluster.Tx(system(ctx), org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		steps := []func(context.Context, uuid.UUID) (int64, error){
			q.DeleteMfaChallengesOfOrg, q.DeleteSessionsOfOrg, q.DeleteEmailVerificationsOfOrg,
			q.DeleteInvitesOfOrg, q.DeleteSignInAttemptsOfOrg, q.DeleteSessionPolicyOfOrg, q.DeleteIdentityProviderOfOrg,
		}
		for _, step := range steps {
			if _, err := step(ctx, org); err != nil {
				return err
			}
		}
		var err error
		remaining, err = q.CountOrgRows(ctx, org)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.PurgeOrgData200JSONResponse{Remaining: int(remaining)}, nil
}

type exportedSession struct {
	ID            uuid.UUID  `json:"id"`
	OrgID         *uuid.UUID `json:"org_id,omitempty"`
	SignedInOrgID uuid.UUID  `json:"signed_in_org_id"`
	UserAgent     *string    `json:"user_agent,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason *string    `json:"revoked_reason,omitempty"`
}

// ExportUserData is the person's sign-in account without its password,
// their sessions on record, and whether a second factor is enrolled.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.ExportUserData403JSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}, nil
	}
	if req.Params.Membership != nil {
		if _, err := orgdata.ParseMemberships(*req.Params.Membership); err != nil {
			fields := map[string]string{"membership": "org_id:membership_id"}
			return api.ExportUserData400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not a membership.", Fields: &fields}}, nil
		}
	}
	type account struct {
		Email           string     `json:"email"`
		EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
		PasswordSet     bool       `json:"password_set"`
		PasswordSetAt   *time.Time `json:"password_set_at,omitempty"`
		CreatedAt       time.Time  `json:"created_at"`
	}
	type mfa struct {
		Enrolled    bool       `json:"enrolled"`
		ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	}
	out := struct {
		UserID       uuid.UUID         `json:"user_id"`
		LocalAccount *account          `json:"local_account"`
		Sessions     []exportedSession `json:"sessions"`
		MFA          mfa               `json:"mfa"`
		Note         string            `json:"note"`
	}{UserID: req.UserId, Sessions: []exportedSession{}, Note: "Secrets are not exported: the password, the authenticator's secret and the recovery codes are left out."}
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		a, err := q.GetLocalAccount(ctx, req.UserId)
		switch {
		case err == nil:
			out.LocalAccount = &account{Email: a.Email, EmailVerifiedAt: timeOf(a.EmailVerifiedAt), PasswordSet: a.PasswordHash.Valid, PasswordSetAt: timeOf(a.PasswordSetAt), CreatedAt: a.CreatedAt.UTC()}
		case err != pgx.ErrNoRows:
			return err
		}
		sessions, err := q.ListSessionsOfUser(ctx, req.UserId)
		if err != nil {
			return err
		}
		for _, row := range sessions {
			out.Sessions = append(out.Sessions, exportedSession{
				ID: row.ID, OrgID: uuidOf(row.ActiveOrgID), SignedInOrgID: row.SignedInOrgID, UserAgent: textOf(row.UserAgent),
				CreatedAt: row.CreatedAt.UTC(), LastSeenAt: row.LastSeenAt.UTC(), ExpiresAt: row.ExpiresAt.UTC(),
				RevokedAt: timeOf(row.RevokedAt), RevokedReason: textOf(row.RevokedReason),
			})
		}
		totp, err := q.GetTotp(ctx, req.UserId)
		switch {
		case err == nil:
			out.MFA = mfa{Enrolled: totp.ConfirmedAt.Valid, ConfirmedAt: timeOf(totp.ConfirmedAt)}
		case err != pgx.ErrNoRows:
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p, err := part(out, nil)
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(p), nil
}

// DeleteUserAccount is a person being deleted: every session ends and is
// pushed, then everything this service keeps about them goes. Idempotent.
func (s *Server) DeleteUserAccount(ctx context.Context, req api.DeleteUserAccountRequestObject) (api.DeleteUserAccountResponseObject, error) {
	if err := auth.RequireService(ctx, "user", "organization"); err != nil {
		return api.DeleteUserAccount403JSONResponse{Code: httpx.CodeForbidden, Message: "The user and organization services only."}, nil
	}
	if _, err := s.revokeAll(ctx, req.UserId, pgtype.UUID{}, reasonAccountDeleted, db.SystemActor(serviceName), scopeUser); err != nil {
		return nil, err
	}
	err := s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		steps := []func(context.Context, uuid.UUID) (int64, error){
			q.DeleteMfaChallengesOfUser, q.DeleteRecoveryCodes, q.DeleteTotp, q.DeleteEmailVerificationsOfUser,
			q.DeleteSessionsOfUser, q.DeleteLocalAccount,
		}
		for _, step := range steps {
			if _, err := step(ctx, req.UserId); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return api.DeleteUserAccount204Response{}, nil
}

// RevokeOrgSessions ends every live session working in an org that is
// closing, and pushes each, so nobody can reach it from now on. Signing in
// again is refused by the screen while it is closing.
func (s *Server) RevokeOrgSessions(ctx context.Context, req api.RevokeOrgSessionsRequestObject) (api.RevokeOrgSessionsResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.RevokeOrgSessions403JSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}, nil
	}
	if !req.Body.Reason.Valid() {
		fields := map[string]string{"reason": "organization_closing"}
		return api.RevokeOrgSessions400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not a reason.", Fields: &fields}}, nil
	}
	reason := string(req.Body.Reason)
	var rows []store.Session
	err := s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).RevokeSessionsOfOrg(ctx, store.RevokeSessionsOfOrgParams{
			OrgID: pgtype.UUID{Bytes: req.OrgId, Valid: true}, Reason: pgtype.Text{String: reason, Valid: true},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if err := s.ended(ctx, row, reason, db.SystemActor(serviceName), scopeUser); err != nil {
			return nil, err
		}
	}
	return api.RevokeOrgSessions200JSONResponse{Revoked: len(rows)}, nil
}
