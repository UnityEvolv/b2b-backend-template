package server

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// SetOrganizationStatus suspends or reactivates an org: platform
// operators only, audited on the org with the reason. Nothing is deleted
// and nobody is removed; identity refuses sessions in a suspended org.
func (s *Server) SetOrganizationStatus(ctx context.Context, req api.SetOrganizationStatusRequestObject) (api.SetOrganizationStatusResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.SetOrganizationStatus403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may suspend or reactivate an organization."}, nil
	}
	if strings.EqualFold(req.OrgId.String(), auth.PlatformOrg) {
		return api.SetOrganizationStatus403JSONResponse{Code: httpx.CodeForbidden, Message: "The platform itself cannot be suspended."}, nil
	}
	status := req.Body.Status
	reason := ""
	if req.Body.Reason != nil {
		reason = strings.TrimSpace(*req.Body.Reason)
	}
	switch {
	case status == api.Closing:
		return api.SetOrganizationStatus400JSONResponse{ErrorJSONResponse: invalid("Close an organization with its close action, which starts the 30 days.", map[string]string{"status": "active or suspended"})}, nil
	case !status.Valid():
		return api.SetOrganizationStatus400JSONResponse{ErrorJSONResponse: invalid("Not a status.", map[string]string{"status": "active or suspended"})}, nil
	case status == api.Suspended && reason == "":
		return api.SetOrganizationStatus400JSONResponse{ErrorJSONResponse: invalid("Say why the organization is suspended.", map[string]string{"reason": "required to suspend"})}, nil
	case len(reason) > 500:
		return api.SetOrganizationStatus400JSONResponse{ErrorJSONResponse: invalid("The reason is too long.", map[string]string{"reason": "at most 500 characters"})}, nil
	}
	var before, org store.Organization
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if before, err = q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		if before.Status == string(status) {
			org = before
			return nil
		}
		// A platform operator reopening a closing org: everything comes back.
		if before.Status == "closing" {
			if status != api.Active {
				return errClosing
			}
			org, err = q.ReopenOrganization(ctx, req.OrgId)
			return err
		}
		org, err = q.SetOrganizationStatus(ctx, store.SetOrganizationStatusParams{OrgID: req.OrgId, Status: string(status), Reason: text(reason)})
		return err
	})
	if errors.Is(err, errClosing) {
		return api.SetOrganizationStatus400JSONResponse{ErrorJSONResponse: invalid("A closing organization can only be reopened.", map[string]string{"status": "active"})}, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetOrganizationStatus404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	if before.Status != org.Status {
		action := "organization.suspended"
		if org.Status == string(api.Active) {
			action = "organization.reactivated"
			if before.Status == "closing" {
				action = "organization.reopened"
			}
		}
		details := map[string]any{"from": before.Status, "to": org.Status}
		if reason != "" {
			details["reason"] = reason
		}
		if err := s.recorder.Record(ctx, audit.Event{OrgID: org.OrgID.String(), Action: action, TargetType: "organization", TargetID: org.OrgID.String(), Details: details}); err != nil {
			return nil, err
		}
	}
	return api.SetOrganizationStatus200JSONResponse(toAPI(org)), nil
}

// supportViewed records on the org's own log that a platform operator, not
// a member, looked at it: the customer sees that staff looked and when.
func (s *Server) supportViewed(ctx context.Context, org store.Organization) error {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.IsService() || strings.EqualFold(c.OrgID, org.OrgID.String()) || !strings.EqualFold(c.OrgID, auth.PlatformOrg) {
		return nil
	}
	return s.recorder.Record(ctx, audit.Event{
		OrgID: org.OrgID.String(), Action: "support.viewed", TargetType: "organization", TargetID: org.OrgID.String(),
		Details: map[string]any{"user_id": c.UserID},
	})
}

var errClosing = errors.New("closing")
