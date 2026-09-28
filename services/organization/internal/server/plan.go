package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

func toPlanLimits(o store.Organization) api.PlanLimits {
	band := plan.Band(o.Plan)
	l := plan.For(band)
	features := make([]string, 0, len(l.Features))
	for _, f := range l.Features {
		features = append(features, string(f))
	}
	return api.PlanLimits{
		OrgId: o.OrgID, Plan: api.Plan(band), Users: l.Users,
		AttachmentBytes: l.AttachmentBytes, Features: features,
	}
}

// GetPlan is the org's plan and its limits, for a service about to gate an
// action. Read every time; nothing here is cached.
func (s *Server) GetPlan(ctx context.Context, req api.GetPlanRequestObject) (api.GetPlanResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetPlan403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	var org store.Organization
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetPlan404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetPlan200JSONResponse(toPlanLimits(org)), nil
}

// PreviewPlanChange is the checklist an admin confirms before a downgrade:
// what closes, and the rule that nothing is deleted and nobody removed.
// An org's own members see it (the admin page shows it before the ask);
// platform operators see it before making the change.
func (s *Server) PreviewPlanChange(ctx context.Context, req api.PreviewPlanChangeRequestObject) (api.PreviewPlanChangeResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil {
		return api.PreviewPlanChange403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	to, err := plan.Parse(string(req.Params.Plan))
	if err != nil {
		return api.PreviewPlanChange400JSONResponse{ErrorJSONResponse: invalid("Not a plan.", map[string]string{"plan": "one of " + bandList()})}, nil
	}
	var org store.Organization
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.PreviewPlanChange404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	from := plan.Band(org.Plan)
	consequences := make([]api.PlanConsequence, 0)
	for _, c := range plan.Downgrade(from, to) {
		consequences = append(consequences, api.PlanConsequence{Code: c.Code, Message: c.Message})
	}
	return api.PreviewPlanChange200JSONResponse(api.PlanChange{
		From: api.Plan(from), To: api.Plan(to), Downgrade: plan.Rank(to) < plan.Rank(from), Consequences: consequences,
	}), nil
}

// ChangePlan moves the org to another band. A platform operator's action
// until billing drives it; audited on the org with both bands. The change is
// only the record: every limit is read at the next action.
func (s *Server) ChangePlan(ctx context.Context, req api.ChangePlanRequestObject) (api.ChangePlanResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.ChangePlan403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may change the plan."}, nil
	}
	to, err := plan.Parse(string(req.Body.Plan))
	if err != nil {
		return api.ChangePlan400JSONResponse{ErrorJSONResponse: invalid("Not a plan.", map[string]string{"plan": "one of " + bandList()})}, nil
	}
	var before, org store.Organization
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if before, err = q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		if before.Plan == string(to) {
			org = before
			return nil
		}
		org, err = q.UpdateOrganizationPlan(ctx, store.UpdateOrganizationPlanParams{OrgID: req.OrgId, Plan: string(to)})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ChangePlan404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	if before.Plan != org.Plan {
		err := s.recorder.Record(ctx, audit.Event{
			OrgID: org.OrgID.String(), Action: "organization.plan.changed",
			TargetType: "organization", TargetID: org.OrgID.String(),
			Details: map[string]any{"from": before.Plan, "to": org.Plan, "downgrade": plan.Rank(to) < plan.Rank(plan.Band(before.Plan))},
		})
		if err != nil {
			return nil, err
		}
	}
	return api.ChangePlan200JSONResponse(toAPI(org)), nil
}

// SetPlanInternal is billing moving the plan: an upgrade, a downgrade, a
// trial, a payment failure. Audited with the reason. An enterprise org is
// invoiced by contract and only a platform operator moves it.
func (s *Server) SetPlanInternal(ctx context.Context, req api.SetPlanInternalRequestObject) (api.SetPlanInternalResponseObject, error) {
	if err := auth.RequireService(ctx, "billing"); err != nil {
		return api.SetPlanInternal403JSONResponse{Code: httpx.CodeForbidden, Message: "The billing service only."}, nil
	}
	to, err := plan.Parse(string(req.Body.Plan))
	if err != nil {
		return api.SetPlanInternal400JSONResponse{ErrorJSONResponse: invalid("Not a plan.", map[string]string{"plan": "one of " + bandList()})}, nil
	}
	var before, org store.Organization
	enterprise := false
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if before, err = q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		if (plan.Band(before.Plan) == plan.Enterprise) != (to == plan.Enterprise) {
			enterprise = true
			return nil
		}
		if before.Plan == string(to) {
			org = before
			return nil
		}
		org, err = q.UpdateOrganizationPlan(ctx, store.UpdateOrganizationPlanParams{OrgID: req.OrgId, Plan: string(to)})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetPlanInternal404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	if enterprise {
		return api.SetPlanInternal409JSONResponse{Code: "plan.enterprise", Message: "Enterprise plans are moved by a platform operator."}, nil
	}
	if before.Plan != org.Plan {
		err := s.recorder.Record(ctx, audit.Event{
			OrgID: org.OrgID.String(), Action: "organization.plan.changed",
			TargetType: "organization", TargetID: org.OrgID.String(),
			Details: map[string]any{"from": before.Plan, "to": org.Plan, "reason": string(req.Body.Reason), "downgrade": plan.Rank(to) < plan.Rank(plan.Band(before.Plan))},
		})
		if err != nil {
			return nil, err
		}
	}
	return api.SetPlanInternal200JSONResponse(toPlanLimits(org)), nil
}
