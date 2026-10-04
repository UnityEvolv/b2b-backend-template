package server

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// The onboarding checklist (docs/onboarding.md). Every step is derived at
// the moment it is read: this service's own steps from its own rows, every
// other from the service that holds the data, asked at once and each within
// onboarding.Timeout. A service that does not answer leaves its step
// unknown; the checklist is still answered. Only dismissals are stored.

// self is this service's name, as a step's Service names it.
const self = "organization"

// allSteps is the whole checklist's dismissal, beside the steps' own.
const allSteps = "*"

// WithOnboarding is s serving the checklist of steps, asking each step's
// service with checker. Without it, the steps are onboarding.Default's and
// those answered elsewhere are unknown.
func (s *Server) WithOnboarding(steps *onboarding.Registry, checker onboarding.Checker) *Server {
	s.steps, s.stepChecker = steps, checker
	return s
}

func (s *Server) onboardingSteps() *onboarding.Registry {
	if s.steps == nil {
		return onboarding.Default
	}
	return s.steps
}

// ownStep is whether one of this service's steps is done for org, or false
// with ok false for a step it does not know.
func ownStep(id string, org store.Organization) (done, ok bool) {
	switch id {
	case onboarding.VerifyDomain:
		return org.Domain.Valid && org.DomainVerifiedAt.Valid, true
	case onboarding.ChoosePlan:
		// Above the lowest band: paid, contractual, or trialing one.
		return plan.Rank(plan.Band(org.Plan)) > 0, true
	}
	return false, false
}

// settingsRefusal is the answer to a caller without the settings permission.
func settingsRefusal(err error) (unauthenticated bool) {
	return errors.Is(err, auth.ErrUnauthenticated)
}

const msgNoSettings = "You do not have permission to see the organization's setup."

// GetOnboarding is the checklist as it stands now.
func (s *Server) GetOnboarding(ctx context.Context, req api.GetOnboardingRequestObject) (api.GetOnboardingResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		if settingsRefusal(err) {
			return api.GetOnboarding401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.GetOnboarding403JSONResponse{Code: authz.Code, Message: msgNoSettings}, nil
	}
	var org store.Organization
	var dismissed []string
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if org, err = q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		dismissed, err = q.ListOnboardingDismissals(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetOnboarding404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	hidden := map[string]bool{}
	for _, d := range dismissed {
		hidden[d] = true
	}

	steps := s.onboardingSteps().Steps()
	out := api.GetOnboarding200JSONResponse{OrgId: req.OrgId, Dismissed: hidden[allSteps], Steps: make([]api.OnboardingStep, len(steps))}
	var wg sync.WaitGroup
	for i, step := range steps {
		out.Steps[i] = api.OnboardingStep{Id: step.ID, Label: step.Label, Href: step.Href, App: step.App, Dismissed: hidden[step.ID]}
		if step.Service == self {
			done, ok := ownStep(step.ID, org)
			out.Steps[i].Done, out.Steps[i].Unknown = done, !ok
			continue
		}
		if s.stepChecker == nil {
			out.Steps[i].Unknown = true
			continue
		}
		wg.Add(1)
		go func(i int, step onboarding.Step) {
			defer wg.Done()
			done, err := s.stepChecker.Done(ctx, step, req.OrgId)
			if err != nil {
				// Shown as unknown, not failed: one service down does not
				// take the checklist with it.
				s.logger.Warn("onboarding step unknown", "step", step.ID, "service", step.Service, "error", err)
				out.Steps[i].Unknown = true
				return
			}
			out.Steps[i].Done = done
		}(i, step)
	}
	wg.Wait()
	out.Complete = true
	for _, st := range out.Steps {
		if st.Unknown || (!st.Done && !st.Dismissed) {
			out.Complete = false
		}
	}
	return out, nil
}

// dismissal hides or shows a step (or, with allSteps, the checklist), and
// audits the change when there was one.
func (s *Server) dismissal(ctx context.Context, org uuid.UUID, step string, hide bool) error {
	var n int64
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if hide {
			n, err = q.DismissOnboarding(ctx, store.DismissOnboardingParams{OrgID: org, StepID: step})
		} else {
			n, err = q.RestoreOnboarding(ctx, store.RestoreOnboardingParams{OrgID: org, StepID: step})
		}
		return err
	})
	if err != nil || n == 0 {
		return err
	}
	ev := audit.Event{OrgID: org.String(), Action: "onboarding.dismissed", TargetType: "organization", TargetID: org.String()}
	if !hide {
		ev.Action = "onboarding.restored"
	}
	if step != allSteps {
		ev.Action, ev.TargetType, ev.TargetID = "onboarding.step_dismissed", "onboarding_step", step
		if !hide {
			ev.Action = "onboarding.step_restored"
		}
	}
	return s.recorder.Record(ctx, ev)
}

// mayDismiss is nil when the caller may change what the org's checklist
// shows: the settings permission.
func (s *Server) mayDismiss(ctx context.Context, org uuid.UUID) error {
	_, err := authz.Require(ctx, s.authz, org.String(), authz.Settings)
	return err
}

const msgNoDismiss = "You do not have permission to change the organization's setup."

// DismissOnboarding hides the whole checklist.
func (s *Server) DismissOnboarding(ctx context.Context, req api.DismissOnboardingRequestObject) (api.DismissOnboardingResponseObject, error) {
	if err := s.mayDismiss(ctx, req.OrgId); err != nil {
		if settingsRefusal(err) {
			return api.DismissOnboarding401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.DismissOnboarding403JSONResponse{Code: authz.Code, Message: msgNoDismiss}, nil
	}
	if err := s.dismissal(ctx, req.OrgId, allSteps, true); err != nil {
		return nil, err
	}
	return api.DismissOnboarding204Response{}, nil
}

// RestoreOnboarding shows the checklist again.
func (s *Server) RestoreOnboarding(ctx context.Context, req api.RestoreOnboardingRequestObject) (api.RestoreOnboardingResponseObject, error) {
	if err := s.mayDismiss(ctx, req.OrgId); err != nil {
		if settingsRefusal(err) {
			return api.RestoreOnboarding401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.RestoreOnboarding403JSONResponse{Code: authz.Code, Message: msgNoDismiss}, nil
	}
	if err := s.dismissal(ctx, req.OrgId, allSteps, false); err != nil {
		return nil, err
	}
	return api.RestoreOnboarding204Response{}, nil
}

// DismissOnboardingStep hides one step.
func (s *Server) DismissOnboardingStep(ctx context.Context, req api.DismissOnboardingStepRequestObject) (api.DismissOnboardingStepResponseObject, error) {
	if err := s.mayDismiss(ctx, req.OrgId); err != nil {
		if settingsRefusal(err) {
			return api.DismissOnboardingStep401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.DismissOnboardingStep403JSONResponse{Code: authz.Code, Message: msgNoDismiss}, nil
	}
	if _, ok := s.onboardingSteps().Step(req.StepId); !ok {
		return api.DismissOnboardingStep404JSONResponse{Code: "onboarding.step_not_found", Message: "No such step."}, nil
	}
	if err := s.dismissal(ctx, req.OrgId, req.StepId, true); err != nil {
		return nil, err
	}
	return api.DismissOnboardingStep204Response{}, nil
}

// RestoreOnboardingStep shows one step again.
func (s *Server) RestoreOnboardingStep(ctx context.Context, req api.RestoreOnboardingStepRequestObject) (api.RestoreOnboardingStepResponseObject, error) {
	if err := s.mayDismiss(ctx, req.OrgId); err != nil {
		if settingsRefusal(err) {
			return api.RestoreOnboardingStep401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.RestoreOnboardingStep403JSONResponse{Code: authz.Code, Message: msgNoDismiss}, nil
	}
	if _, ok := s.onboardingSteps().Step(req.StepId); !ok {
		return api.RestoreOnboardingStep404JSONResponse{Code: "onboarding.step_not_found", Message: "No such step."}, nil
	}
	if err := s.dismissal(ctx, req.OrgId, req.StepId, false); err != nil {
		return nil, err
	}
	return api.RestoreOnboardingStep204Response{}, nil
}
