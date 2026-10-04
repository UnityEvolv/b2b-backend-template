package server

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oapi-codegen/nullable"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Per-org entitlement overrides: a platform operator's exceptions to an
// org's band for an enterprise deal. Each is one row, read with the band at
// the moment of every action; one past its end simply stops applying.

// toOverride is a row as pkg/plan reads it.
func toOverride(row store.PlanOverride) plan.Override {
	o := plan.Override{}
	if row.Kind == "limit" {
		o.Limit, o.Cap = plan.Limit(row.Key), int(row.Cap.Int32)
	} else {
		o.Feature, o.Allowed = plan.Feature(row.Key), row.Allowed.Bool
	}
	if row.EndsAt.Valid {
		t := row.EndsAt.Time.UTC()
		o.EndsAt = &t
	}
	return o
}

// toAPIOverride is an override as the API shows it, in force at now or not.
func toAPIOverride(o plan.Override, now time.Time) api.PlanOverride {
	out := api.PlanOverride{Key: o.Key(), InForce: o.InForce(now)}
	if o.Limit != "" {
		cap := o.Cap
		out.Kind, out.Cap = api.PlanOverrideKindLimit, &cap
	} else {
		allowed := o.Allowed
		out.Kind, out.Allowed = api.PlanOverrideKindFeature, &allowed
	}
	if o.EndsAt != nil {
		out.EndsAt = nullable.NewNullableWithValue(*o.EndsAt)
	}
	return out
}

// entitlements is org's band and every override it has, ended or not:
// pkg/plan ignores the ended ones at the moment of each check.
func entitlements(ctx context.Context, q *store.Queries, org store.Organization) (plan.Entitlements, error) {
	rows, err := q.ListPlanOverrides(ctx, org.OrgID)
	if err != nil {
		return plan.Entitlements{}, err
	}
	e := plan.Of(plan.Band(org.Plan))
	for _, row := range rows {
		e.Overrides = append(e.Overrides, toOverride(row))
	}
	return e, nil
}

// inForce is the overrides in force now, for the API.
func (s *Server) inForce(d plan.Description) []api.PlanOverride {
	now := s.now()
	out := make([]api.PlanOverride, 0, len(d.Overrides))
	for _, o := range d.Overrides {
		out = append(out, toAPIOverride(o, now))
	}
	return out
}

// orgAndOverrides reads the org and its overrides in one read.
func (s *Server) orgAndOverrides(ctx context.Context, id uuid.UUID) (store.Organization, plan.Entitlements, error) {
	var org store.Organization
	var e plan.Entitlements
	err := s.cluster.Read(ctx, id.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if org, err = q.GetOrganization(ctx, id); err != nil {
			return err
		}
		e, err = entitlements(ctx, q, org)
		return err
	})
	return org, e, err
}

var errNoOverride = errors.New("no such override")

// ListPlanOverrides is every override the org has, in force or ended, for
// the platform console.
func (s *Server) ListPlanOverrides(ctx context.Context, req api.ListPlanOverridesRequestObject) (api.ListPlanOverridesResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.ListPlanOverrides403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may see an organization's overrides."}, nil
	}
	_, e, err := s.orgAndOverrides(ctx, req.OrgId)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ListPlanOverrides404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := api.PlanOverrideList{Overrides: make([]api.PlanOverride, 0, len(e.Overrides))}
	for _, o := range e.Overrides {
		out.Overrides = append(out.Overrides, toAPIOverride(o, now))
	}
	return api.ListPlanOverrides200JSONResponse(out), nil
}

// SetPlanOverride sets the org's override of one registered limit or
// feature, replacing any it had. Audited on the org, so its own audit log
// shows what changed and until when.
func (s *Server) SetPlanOverride(ctx context.Context, req api.SetPlanOverrideRequestObject) (api.SetPlanOverrideResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.SetPlanOverride403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may set an override."}, nil
	}
	in := req.Body
	if in == nil {
		in = &api.PlanOverrideInput{}
	}
	o := plan.Override{}
	params := store.UpsertPlanOverrideParams{OrgID: req.OrgId, Kind: string(req.Kind), Key: req.Key}
	switch req.Kind {
	case "limit":
		if in.Cap == nil || in.Allowed != nil {
			return api.SetPlanOverride400JSONResponse{ErrorJSONResponse: invalid("A limit's override is a cap.", map[string]string{"cap": "required for a limit; allowed is for a feature"})}, nil
		}
		o.Limit, o.Cap = plan.Limit(req.Key), *in.Cap
		params.Cap = pgtype.Int4{Int32: int32(*in.Cap), Valid: true}
	case "feature":
		if in.Allowed == nil || in.Cap != nil {
			return api.SetPlanOverride400JSONResponse{ErrorJSONResponse: invalid("A feature's override grants or takes it away.", map[string]string{"allowed": "required for a feature; cap is for a limit"})}, nil
		}
		o.Feature, o.Allowed = plan.Feature(req.Key), *in.Allowed
		params.Allowed = pgtype.Bool{Bool: *in.Allowed, Valid: true}
	default:
		return api.SetPlanOverride400JSONResponse{ErrorJSONResponse: invalid("Not a kind of override.", map[string]string{"kind": "limit or feature"})}, nil
	}
	if err := plan.Default.CheckOverride(o); err != nil {
		return api.SetPlanOverride400JSONResponse{ErrorJSONResponse: invalid("Not a registered "+string(req.Kind)+".", map[string]string{"key": "a " + string(req.Kind) + " this deployment registers"})}, nil
	}
	if in.EndsAt.IsSpecified() && !in.EndsAt.IsNull() {
		end := in.EndsAt.MustGet().UTC()
		if !end.After(s.now()) {
			return api.SetPlanOverride400JSONResponse{ErrorJSONResponse: invalid("The end is in the past.", map[string]string{"ends_at": "a time in the future, or none"})}, nil
		}
		o.EndsAt = &end
		params.EndsAt = pgtype.Timestamptz{Time: end, Valid: true}
	}
	var before *plan.Override
	var row store.PlanOverride
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		prev, err := q.GetPlanOverride(ctx, store.GetPlanOverrideParams{OrgID: req.OrgId, Kind: params.Kind, Key: params.Key})
		switch {
		case err == nil:
			p := toOverride(prev)
			before = &p
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		row, err = q.UpsertPlanOverride(ctx, params)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetPlanOverride404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	details := overrideDetails(o)
	if before != nil {
		details["previous"] = overrideDetails(*before)
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "organization.plan.override_set",
		TargetType: "organization", TargetID: req.OrgId.String(), Details: details,
	}); err != nil {
		return nil, err
	}
	return api.SetPlanOverride200JSONResponse(toAPIOverride(toOverride(row), s.now())), nil
}

// RemovePlanOverride removes the org's override of one limit or feature:
// the band's value applies from the next action. Audited on the org.
func (s *Server) RemovePlanOverride(ctx context.Context, req api.RemovePlanOverrideRequestObject) (api.RemovePlanOverrideResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.RemovePlanOverride403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may remove an override."}, nil
	}
	var removed store.PlanOverride
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		removed, err = store.New(tx).DeletePlanOverride(ctx, store.DeletePlanOverrideParams{OrgID: req.OrgId, Kind: string(req.Kind), Key: req.Key})
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoOverride
		}
		return err
	})
	if errors.Is(err, errNoOverride) {
		return api.RemovePlanOverride404JSONResponse{Code: "plan.override_not_found", Message: "The organization has no such override."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "organization.plan.override_removed",
		TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"previous": overrideDetails(toOverride(removed))},
	}); err != nil {
		return nil, err
	}
	return api.RemovePlanOverride204Response{}, nil
}

// overrideDetails is an override in an audit entry: keys and values only.
func overrideDetails(o plan.Override) map[string]any {
	d := map[string]any{}
	if o.Limit != "" {
		d["kind"], d["key"], d["cap"] = "limit", string(o.Limit), o.Cap
	} else {
		d["kind"], d["key"], d["allowed"] = "feature", string(o.Feature), o.Allowed
	}
	if o.EndsAt != nil {
		d["ends_at"] = o.EndsAt.Format(time.RFC3339)
	}
	return d
}
