package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// GetOnboardingStep says whether one of this service's onboarding steps is
// done for an org, derived now from its rows (docs/onboarding.md): the
// organization service asks while it reads the org's checklist.
func (s *Server) GetOnboardingStep(ctx context.Context, req api.GetOnboardingStepRequestObject) (api.GetOnboardingStepResponseObject, error) {
	if err := auth.RequireService(ctx, onboarding.Caller); err != nil {
		return api.GetOnboardingStep403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}}, nil
	}
	switch req.StepId {
	case onboarding.InviteTeammates:
		var sent int64
		err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
			var err error
			sent, err = store.New(tx).CountInvitesOfOrg(ctx, req.OrgId)
			return err
		})
		if err != nil {
			return nil, err
		}
		if sent > 0 {
			return api.GetOnboardingStep200JSONResponse{Done: true}, nil
		}
		// Or a second member, however they came (signed in through the
		// org's provider, SCIM, an import).
		members, err := s.users.CountMembers(ctx, req.OrgId)
		if err != nil {
			return nil, err
		}
		return api.GetOnboardingStep200JSONResponse{Done: members > 1}, nil
	case onboarding.SetUpSSO:
		var p store.IdentityProvider
		err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
			var err error
			p, err = store.New(tx).GetIdentityProvider(ctx, req.OrgId)
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return api.GetOnboardingStep200JSONResponse{Done: false}, nil
		}
		if err != nil {
			return nil, err
		}
		return api.GetOnboardingStep200JSONResponse{Done: p.Status == "active"}, nil
	}
	return api.GetOnboardingStep404JSONResponse{Code: "onboarding.step_not_found", Message: "Not a step this service answers."}, nil
}
