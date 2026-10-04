package server

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/store"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
)

// GetOnboardingStep answers the onboarding checklist's question for the
// product's one step (pkg/onboarding): has the org made a project? Asked
// by the organization service when it reads the checklist, and derived now
// from the table, so a project made, or the last one deleted, shows on the
// next read.
func (s *Server) GetOnboardingStep(ctx context.Context, req api.GetOnboardingStepRequestObject) (api.GetOnboardingStepResponseObject, error) {
	if auth.RequireService(ctx, onboarding.Caller) != nil {
		return api.GetOnboardingStep403JSONResponse{ErrorJSONResponse: notOrganization}, nil
	}
	if req.StepId != product.FirstProject {
		return api.GetOnboardingStep404JSONResponse{Code: "onboarding.step_not_found", Message: "Not a step this service answers."}, nil
	}
	var n int64
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		n, err = store.New(tx).CountProjects(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.GetOnboardingStep200JSONResponse{Done: n > 0}, nil
}
