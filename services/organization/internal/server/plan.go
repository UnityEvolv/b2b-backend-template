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
	d := plan.Describe(plan.Band(o.Plan))
	return api.PlanLimits{OrgId: o.OrgID, Plan: api.Plan(d.Band), Contractual: d.Contractual, Limits: d.Limits, Features: d.Features}
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
// trial, a payment failure. Audited with the reason. An org on a contractual
// band is invoiced by contract and only a platform operator moves it.
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
		if plan.Contractual(plan.Band(before.Plan)) != plan.Contractual(to) {
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
		return api.SetPlanInternal409JSONResponse{Code: "plan.contractual", Message: "A contractual plan is moved by a platform operator."}, nil
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

// ListPlans is the plan catalogue: every band, lowest first, with its
// label, its caps and its features, and every limit and feature with its
// label. The same in every org, to anyone signed in; read from the registry
// now, so what the product registered at start is what the page shows.
func (s *Server) ListPlans(ctx context.Context, _ api.ListPlansRequestObject) (api.ListPlansResponseObject, error) {
	limits := plan.Default.Limits()
	out := api.PlanCatalogue{Bands: []api.PlanBand{}, Limits: make([]api.PlanLimitInfo, 0, len(limits)), Features: []api.PlanFeatureInfo{}}
	for _, b := range plan.Ladder() {
		d := plan.Describe(b.Name)
		out.Bands = append(out.Bands, api.PlanBand{Name: api.Plan(d.Band), Label: d.Label, Contractual: d.Contractual, Limits: d.Limits, Features: d.Features})
	}
	for _, l := range limits {
		out.Limits = append(out.Limits, api.PlanLimitInfo{Key: string(l.Key), Label: l.Label})
	}
	for _, f := range plan.Default.Features() {
		out.Features = append(out.Features, api.PlanFeatureInfo{Key: string(f.Key), Label: f.Label})
	}
	return api.ListPlans200JSONResponse(out), nil
}

// GetOrganizationPlan is the org's plan as its own people see it: the band,
// what it allows, and what the org uses now of the limits the template
// counts. For the org's members and platform operators, as the downgrade
// checklist is. Nothing is cached; the usage is asked of the user service
// now, and left out, with a warning, when it cannot answer, since the page
// is informational and the gate is the action itself.
func (s *Server) GetOrganizationPlan(ctx context.Context, req api.GetOrganizationPlanRequestObject) (api.GetOrganizationPlanResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil {
		return api.GetOrganizationPlan403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var org store.Organization
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetOrganizationPlan404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	d := plan.Describe(plan.Band(org.Plan))
	out := api.OrganizationPlan{OrgId: org.OrgID, Plan: api.Plan(d.Band), Label: d.Label, Contractual: d.Contractual,
		Limits: d.Limits, Features: d.Features, Usage: map[string]int{}}
	if s.deps.Users != nil {
		active, err := s.deps.Users.CountMembers(ctx, org.OrgID)
		if err != nil {
			s.logger.Warn("member count not read for the plan page", "org_id", org.OrgID, "error", err)
		} else {
			out.Usage[string(plan.Users)] = active
		}
	}
	return api.GetOrganizationPlan200JSONResponse(out), nil
}
