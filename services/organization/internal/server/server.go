// Package server implements the organization API: the generated interface in
// internal/api, backed by the generated queries in internal/store.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Server answers the organization API.
type Server struct {
	cluster  *db.Cluster
	logger   *slog.Logger
	recorder audit.Recorder
	wrapper  kms.Wrapper
	authz    authz.Checker
	deps     Deps
	// apps is each web app's origin, by name: where a signup link opens.
	apps map[string]string
	// brand is how the product names itself in exports and DNS records.
	brand Branding
	// off is what offboarding and exports call out to.
	off Offboarding
	// steps is the onboarding checklist, and stepChecker asks the other
	// services whether theirs are done (WithOnboarding).
	steps       *onboarding.Registry
	stepChecker onboarding.Checker
}

// WithOffboarding is s with the offboarding and export dependencies.
func (s *Server) WithOffboarding(off Offboarding) *Server {
	s.off = off
	return s
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API on cluster. recorder is where admin actions are audited;
// wrapper is the KMS master key that wraps each org's data key; deps are
// the other services signup calls; apps is each web app's origin.
func New(cluster *db.Cluster, logger *slog.Logger, recorder audit.Recorder, wrapper kms.Wrapper, checker authz.Checker, deps Deps, apps map[string]string) *Server {
	return &Server{cluster: cluster, logger: logger, recorder: recorder, wrapper: wrapper, authz: checker, deps: deps, apps: apps, brand: DefaultBranding}
}

// Branding is how the product names itself here: as the author of a
// personal data export, and in the DNS record that proves a domain.
type Branding struct {
	// Product is the product's name.
	Product string
	// TXTPrefix goes before the domain to name the verification record:
	// by default "_<product id>-verify.", a TXT at that name under the domain.
	TXTPrefix string
	// TXTValuePrefix goes before the token in that record's value.
	TXTValuePrefix string
}

// DefaultBranding is the template's own names, for a product that sets none.
var DefaultBranding = Branding{Product: config.DefaultBrand.Name, TXTPrefix: config.DefaultBrand.TXTPrefix(), TXTValuePrefix: config.DefaultBrand.TXTValuePrefix()}

// WithBranding is s naming the product b; an empty field keeps the default.
func (s *Server) WithBranding(b Branding) *Server {
	if b.Product != "" {
		s.brand.Product = b.Product
	}
	if b.TXTPrefix != "" {
		s.brand.TXTPrefix = b.TXTPrefix
	}
	if b.TXTValuePrefix != "" {
		s.brand.TXTValuePrefix = b.TXTValuePrefix
	}
	return s
}

// Wrapper is the KMS master key this service wraps org keys with. A test
// hands the same one to the service under test.
func (s *Server) Wrapper() kms.Wrapper { return s.wrapper }

// Limits is this API's rate limits: one line per endpoint. An
// endpoint not listed is limited only by the per-address ceiling.
var Limits = map[string]ratelimit.Bound{
	"POST /v1/organizations":                                                 ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/organizations":                                                  ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}":                                         ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PATCH /v1/organizations/{org_id}":                                       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/plans":                                                          ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/plan":                                    ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/plan":                                    ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/plan-change":                             ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/plan-overrides":                          ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"PUT /v1/organizations/{org_id}/plan-overrides/{kind}/{key}":             ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"DELETE /v1/organizations/{org_id}/plan-overrides/{kind}/{key}":          ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/signups":                                                       ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/signups/complete":                                              ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/organizations/{org_id}/close":                                  ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/organizations/{org_id}/reopen":                                 ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/organizations/{org_id}/reopen-link":                            ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/organizations/{org_id}/retention":                               ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"PUT /v1/organizations/{org_id}/retention":                               ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/organizations/{org_id}/exports":                                ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/exports":                                 ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"POST /v1/me/exports":                                                    ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/me/exports":                                                     ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/domain":                                  ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/domain":                                  ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/domain/verify":                          ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/onboarding":                              ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/onboarding/dismissal":                   ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/onboarding/dismissal":                 ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/onboarding/steps/{step_id}/dismissal":   ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/onboarding/steps/{step_id}/dismissal": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
}

// Handler is the API's routes, with bad requests and failures answered in the
// error envelope. middlewares run after routing, per endpoint.
func (s *Server) Handler(mux *http.ServeMux, middlewares ...api.MiddlewareFunc) http.Handler {
	strict := api.NewStrictHandlerWithOptions(s, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request could not be read.")
		},
		ResponseErrorHandlerFunc: s.internalError,
	})
	return api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseRouter:  mux,
		Middlewares: middlewares,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			// A path parameter that is not what the contract says, such as an
			// org_id that is not a uuid.
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request is not valid.")
		},
	})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "route", r.Pattern, "error", err)
	httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Something went wrong.")
}

// GetOrganization is one organization, to a caller whose token is for it or
// to a platform operator.
//
// A token for another org gets 403, not 404, and the same 403 whether or not
// that org exists, so a caller learns nothing about orgs they are not in.
// Which members may read it is the role check in pkg/authz.
func (s *Server) GetOrganization(ctx context.Context, req api.GetOrganizationRequestObject) (api.GetOrganizationResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil {
		return api.GetOrganization403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var org store.Organization
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetOrganization404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.supportViewed(ctx, org); err != nil {
		return nil, err
	}
	return api.GetOrganization200JSONResponse(toAPI(org)), nil
}
