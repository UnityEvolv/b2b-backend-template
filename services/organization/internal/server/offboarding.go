package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Offboarding and retention (UO-183): closing an org, reopening it within
// the grace, the schedule of what is kept, and the purge at the end.

// closeGrace is how long a closing org can be reopened before it is purged.
const closeGrace = 30 * 24 * time.Hour

// Platform is what closing, purging and exporting ask of the other
// services, each over its own API.
type Platform interface {
	// RevokeOrgSessions ends every session in the org, pushed to open sockets.
	RevokeOrgSessions(ctx context.Context, org uuid.UUID) error
	// CloseBilling cancels the org's paid subscription.
	CloseBilling(ctx context.Context, org uuid.UUID) error
	// ExpireAudit deletes the org's audit events older than before.
	ExpireAudit(ctx context.Context, org uuid.UUID, before time.Time) error
	// Person is a user's sign-in address and their memberships.
	Person(ctx context.Context, user uuid.UUID) (Person, error)
}

// Person is what an export or a notice needs of a user.
type Person struct {
	Email       string
	Memberships []orgdata.Membership
}

// Data is every data owner's endpoints (orgdata.Client).
type Data interface {
	Export(ctx context.Context, o dataowner.Owner, org uuid.UUID) (orgdata.Part, error)
	Purge(ctx context.Context, o dataowner.Owner, org uuid.UUID) (int, error)
	ExportUser(ctx context.Context, o dataowner.Owner, user uuid.UUID, memberships []orgdata.Membership) (orgdata.Part, error)
}

// Files is object storage, as exports and purges use it.
type Files interface {
	Put(ctx context.Context, orgID string, key storage.Key, contentType string, size int64, body io.Reader) error
	Get(ctx context.Context, orgID string, key storage.Key) (io.ReadCloser, string, error)
	Delete(ctx context.Context, orgID string, key storage.Key) error
	DeleteAll(ctx context.Context, orgID, purpose string) (int, error)
	ReadURL(ctx context.Context, orgID string, key storage.Key, ttl time.Duration) (*url.URL, error)
}

// Offboarding is what the offboarding and export paths depend on. Zero
// values are for tests that do not touch them.
type Offboarding struct {
	Platform Platform
	Data     Data
	Files    Files
	// Owners is the services that hold org data, located (Registry.Locate):
	// an export gathers a part from every exporter and a purge empties
	// every purger, in the registry's order. Nil is dataowner.Default.
	Owners *dataowner.Registry
	// Live is the live-session bus a close is pushed on (org.suspended).
	Live livebus.Publisher
	Now  func() time.Time
}

func (s *Server) owners() *dataowner.Registry {
	if s.off.Owners != nil {
		return s.off.Owners
	}
	return dataowner.Default
}

func (s *Server) now() time.Time {
	if s.off.Now != nil {
		return s.off.Now()
	}
	return time.Now()
}

// CloseOrganization closes the org: the Owner, typing its name, or a
// platform operator with a reason. Sessions end now; nothing is deleted.
func (s *Server) CloseOrganization(ctx context.Context, req api.CloseOrganizationRequestObject) (api.CloseOrganizationResponseObject, error) {
	c, ok := auth.CallerFrom(ctx)
	if !ok {
		return api.CloseOrganization401JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}), nil
	}
	platform := !c.IsService() && strings.EqualFold(c.OrgID, auth.PlatformOrg)
	if !platform {
		if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.DeleteOrganization); err != nil {
			return api.CloseOrganization403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only the Owner may close the organization."}), nil
		}
	}
	if strings.EqualFold(req.OrgId.String(), auth.PlatformOrg) {
		return api.CloseOrganization403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The platform itself cannot be closed."}), nil
	}
	reason := ""
	if req.Body.Reason != nil {
		reason = strings.TrimSpace(*req.Body.Reason)
	}
	if platform && reason == "" {
		return api.CloseOrganization400JSONResponse{ErrorJSONResponse: invalid("Say why the organization is closed.", map[string]string{"reason": "required of a platform operator"})}, nil
	}
	var before store.Organization
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		before, err = store.New(tx).GetOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CloseOrganization404JSONResponse(api.ErrorJSONResponse{Code: "organization.not_found", Message: "No such organization."}), nil
	}
	if err != nil {
		return nil, err
	}
	if before.Status == "closing" {
		return api.CloseOrganization409JSONResponse(api.ErrorJSONResponse{Code: "organization.closing", Message: "The organization is already closing."}), nil
	}
	if strings.TrimSpace(req.Body.ConfirmName) != before.Name {
		return api.CloseOrganization400JSONResponse{ErrorJSONResponse: invalid("Type the organization's name exactly to confirm.", map[string]string{"confirm_name": "does not match"})}, nil
	}
	raw, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	now := s.now()
	params := store.CloseOrganizationParams{
		OrgID: req.OrgId, ClosingAt: pgtype.Timestamptz{Time: now, Valid: true}, PurgeAfter: pgtype.Timestamptz{Time: now.Add(closeGrace), Valid: true},
		ReopenTokenHash: hash,
	}
	if reason != "" {
		params.Reason = pgtype.Text{String: reason, Valid: true}
	}
	if u, err := uuid.Parse(c.UserID); err == nil && !platform {
		params.ClosedByUserID = pgtype.UUID{Bytes: u, Valid: true}
	}
	var org store.Organization
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).CloseOrganization(ctx, params)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CloseOrganization409JSONResponse(api.ErrorJSONResponse{Code: "organization.closing", Message: "The organization is already closing."}), nil
	}
	if err != nil {
		return nil, err
	}
	details := map[string]any{"purge_after": now.Add(closeGrace).UTC().Format(time.RFC3339), "by_platform": platform}
	if reason != "" {
		details["reason"] = reason
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.OrgID.String(), Action: "organization.closing", TargetType: "organization", TargetID: org.OrgID.String(), Details: details}); err != nil {
		return nil, err
	}
	// Unreachable within a minute, and no longer charged. Each is retried by
	// the next close attempt's operator if it fails; the org is closing
	// either way, and sign-in refuses it from now.
	if s.off.Platform != nil {
		if err := s.off.Platform.RevokeOrgSessions(ctx, org.OrgID); err != nil {
			s.logger.Error("closing org: sessions not revoked", "org_id", org.OrgID, "error", err)
		}
		if err := s.off.Platform.CloseBilling(ctx, org.OrgID); err != nil {
			s.logger.Error("closing org: subscription not cancelled", "org_id", org.OrgID, "error", err)
		}
	}
	// Everyone with it open is told now, whatever the sessions' state.
	if s.off.Live != nil {
		if err := s.off.Live.Publish(ctx, livebus.Event{Type: livebus.OrgSuspended, OrgID: org.OrgID.String(), Code: "organization_closing",
			Message: "This organization is closing. An Owner can reopen it from the link in the email sent when it closed."}); err != nil {
			s.logger.Warn("closing org: not pushed live", "org_id", org.OrgID, "error", err)
		}
	}
	s.tellOwners(ctx, org, raw)
	return api.CloseOrganization200JSONResponse(toAPI(org)), nil
}

// tellOwners emails the reopen link to whoever closed the org and to its
// owner of record.
func (s *Server) tellOwners(ctx context.Context, org store.Organization, token string) {
	if s.deps.Email == nil || s.off.Platform == nil || !org.PurgeAfter.Valid {
		return
	}
	link := s.apps["admin"] + "/reopen?org=" + org.OrgID.String() + "&token=" + url.QueryEscape(token)
	sent := map[string]bool{}
	for _, id := range []pgtype.UUID{org.ClosedByUserID, org.OwnerUserID} {
		if !id.Valid {
			continue
		}
		p, err := s.off.Platform.Person(ctx, uuid.UUID(id.Bytes))
		if err != nil {
			s.logger.Error("closing org: owner not reached", "org_id", org.OrgID, "user_id", uuid.UUID(id.Bytes), "error", err)
			continue
		}
		if p.Email == "" || sent[p.Email] {
			continue
		}
		sent[p.Email] = true
		if _, err := s.deps.Email.Send(ctx, email.Message{
			OrgID: org.OrgID.String(), OrgName: org.Name, To: p.Email, Template: "organization_closing",
			Data: map[string]any{"purge_date": org.PurgeAfter.Time.UTC().Format("2 January 2006"), "link": link},
		}); err != nil {
			s.logger.Error("closing org: owner not told", "org_id", org.OrgID, "error", err)
		}
	}
}

// ReopenOrganization reverses a close within the grace, with the emailed
// link: everything comes back as it was.
func (s *Server) ReopenOrganization(ctx context.Context, req api.ReopenOrganizationRequestObject) (api.ReopenOrganizationResponseObject, error) {
	var org store.Organization
	gone := false
	err := s.cluster.Tx(db.WithActor(ctx, db.SystemActor(orgdata.Caller)), req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		o, err := q.GetOrganization(ctx, req.OrgId)
		if err != nil {
			return err
		}
		if o.Status != "closing" || len(o.ReopenTokenHash) == 0 || !bytes.Equal(o.ReopenTokenHash, hashSecret(req.Body.Token)) {
			return pgx.ErrNoRows
		}
		if o.PurgeAfter.Valid && s.now().After(o.PurgeAfter.Time) {
			gone = true
			return nil
		}
		org, err = q.ReopenOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ReopenOrganization404JSONResponse(api.ErrorJSONResponse{Code: "organization.reopen_invalid", Message: "This link does not reopen an organization. Ask for a new one from the sign-in page."}), nil
	}
	if err != nil {
		return nil, err
	}
	if gone {
		return api.ReopenOrganization410JSONResponse(api.ErrorJSONResponse{Code: "organization.purged", Message: "The organization's 30 days are over; it is being deleted."}), nil
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.OrgID.String(), Action: "organization.reopened", TargetType: "organization", TargetID: org.OrgID.String(),
		// The emailed link reopened it; nobody is signed in.
		Actor: db.SystemActor("reopen-link")}); err != nil {
		return nil, err
	}
	return api.ReopenOrganization200JSONResponse{OrgId: org.OrgID, Status: api.OrganizationStatus(org.Status)}, nil
}

// RequestReopenLink emails a fresh reopen link to a closing org's owners.
// The answer is the same whatever happened, so it tells nobody anything.
func (s *Server) RequestReopenLink(ctx context.Context, req api.RequestReopenLinkRequestObject) (api.RequestReopenLinkResponseObject, error) {
	raw, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	var org store.Organization
	err = s.cluster.Tx(db.WithActor(ctx, db.SystemActor(orgdata.Caller)), req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if org, err = q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		if org.Status != "closing" {
			return pgx.ErrNoRows
		}
		return q.SetReopenToken(ctx, store.SetReopenTokenParams{OrgID: req.OrgId, ReopenTokenHash: hash})
	})
	if err == nil {
		s.tellOwners(ctx, org, raw)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("reopen link failed", "org_id", req.OrgId, "error", err)
	}
	return api.RequestReopenLink202Response{}, nil
}

// retention is the schedule, the same words for every org; only the
// audit period varies.
func retention(o store.Organization) api.Retention {
	months := int(o.AuditMonths)
	audit := fmt.Sprintf("%d months, then deleted.", months)
	return api.Retention{
		AuditMonths:       months,
		AuditConfigurable: plan.Contractual(plan.Band(o.Plan)),
		Classes: []struct {
			Class api.RetentionClassesClass `json:"class"`
			Kept  string                    `json:"kept"`
		}{
			{Class: api.Identity, Kept: "For as long as the membership lasts; 30 days after someone is deactivated or leaves, their name, email and directory details are removed. The membership stays as an id so records still add up."},
			{Class: api.Audit, Kept: audit},
			{Class: api.Transient, Kept: "Sessions, invites and tokens: gone when they expire."},
			{Class: api.Backups, Kept: "30 days rolling, so deleted data can survive in backups for up to 30 days."},
		},
	}
}

// GetRetention is the schedule that applies to the org: its admins and
// the platform.
func (s *Server) GetRetention(ctx context.Context, req api.GetRetentionRequestObject) (api.GetRetentionResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.GetRetention403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to see this."}), nil
	}
	o, err := s.get(ctx, req.OrgId)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetRetention404JSONResponse(api.ErrorJSONResponse{Code: "organization.not_found", Message: "No such organization."}), nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetRetention200JSONResponse(retention(o)), nil
}

// SetRetention lengthens (or restores) the audit log's retention: platform
// operators, and beyond 13 months only on a contractual plan.
func (s *Server) SetRetention(ctx context.Context, req api.SetRetentionRequestObject) (api.SetRetentionResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.SetRetention403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may change retention."}), nil
	}
	months := req.Body.AuditMonths
	if months < 13 || months > 84 {
		return api.SetRetention400JSONResponse{ErrorJSONResponse: invalid("Between 13 months and 7 years.", map[string]string{"audit_months": "13 to 84"})}, nil
	}
	var o store.Organization
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		cur, err := q.GetOrganization(ctx, req.OrgId)
		if err != nil {
			return err
		}
		if months != 13 && !plan.Contractual(plan.Band(cur.Plan)) {
			return errNotContractual
		}
		o, err = q.SetAuditMonths(ctx, store.SetAuditMonthsParams{OrgID: req.OrgId, AuditMonths: int32(months)})
		return err
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return api.SetRetention404JSONResponse(api.ErrorJSONResponse{Code: "organization.not_found", Message: "No such organization."}), nil
	case errors.Is(err, errNotContractual):
		return api.SetRetention400JSONResponse{ErrorJSONResponse: invalid("A longer audit retention is for organizations on a contractual plan.", map[string]string{"audit_months": "13 unless the plan is contractual"})}, nil
	case err != nil:
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: o.OrgID.String(), Action: "organization.retention_changed", TargetType: "organization", TargetID: o.OrgID.String(), Details: map[string]any{"audit_months": months}}); err != nil {
		return nil, err
	}
	return api.SetRetention200JSONResponse(retention(o)), nil
}

var errNotContractual = errors.New("not contractual")

func (s *Server) get(ctx context.Context, org uuid.UUID) (store.Organization, error) {
	var o store.Organization
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		o, err = store.New(tx).GetOrganization(ctx, org)
		return err
	})
	return o, err
}

// readsSettings is an org admin holding settings, or the platform.
func (s *Server) readsSettings(ctx context.Context, org uuid.UUID) error {
	if auth.RequirePlatform(ctx) == nil {
		return nil
	}
	_, err := authz.Require(ctx, s.authz, org.String(), authz.Settings)
	return err
}
