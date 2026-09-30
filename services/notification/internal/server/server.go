// Package server implements the notification API: queueing email into the
// outbox for the sender loop, and reading a queued email's state.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Server answers the notification API.
type Server struct {
	cluster *db.Cluster
	logger  *slog.Logger
	n       *Notifications
	// product is the name emails are sent as.
	product string
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API on cluster, sending emails as the template's default
// product name.
func New(cluster *db.Cluster, logger *slog.Logger) *Server {
	return &Server{cluster: cluster, logger: logger, product: config.DefaultBrand.Name}
}

// WithProduct is s sending emails as product.
func (s *Server) WithProduct(product string) *Server {
	s.product = product
	return s
}

// Limits is this API's rate limits: the outbox endpoints are for services,
// which are not limited; the rest are people's (UO-119).
var Limits = map[string]ratelimit.Bound{
	"GET /v1/organizations/{org_id}/notifications":                  ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/notifications/read":            ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/notification-preferences":       ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/notification-preferences":       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/notification-preferences/test": ratelimit.On(ratelimit.InviteSend, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/notification-settings":          ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/notification-settings":          ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/devices":                       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/devices/unregister":            ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/notification-categories":                               ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
}

// Handler is the API's routes, with bad requests and failures answered in the
// error envelope.
func (s *Server) Handler(mux *http.ServeMux, middlewares ...api.MiddlewareFunc) http.Handler {
	strict := api.NewStrictHandlerWithOptions(s, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request could not be read.")
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logger.Error("request failed", "route", r.Pattern, "error", err)
			httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Something went wrong.")
		},
	})
	return api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseRouter:  mux,
		Middlewares: middlewares,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request is not valid.")
		},
	})
}

// QueueEmail renders the template and puts the email in the outbox. Services
// only. An address that bounced before is recorded as suppressed rather than
// sent again.
func (s *Server) QueueEmail(ctx context.Context, req api.QueueEmailRequestObject) (api.QueueEmailResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.QueueEmail403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a service sends email."}, nil
	}
	in := req.Body
	to := string(in.To)
	fields := map[string]string{}
	if _, err := mail.ParseAddress(to); err != nil {
		fields["to"] = "an email address"
	}
	if strings.TrimSpace(in.OrgName) == "" || len(in.OrgName) > 200 {
		fields["org_name"] = "required, at most 200 characters"
	}
	if _, ok := email.Templates[in.Template]; !ok {
		fields["template"] = "a template from pkg/email"
	}
	if len(fields) > 0 {
		return api.QueueEmail400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	var data map[string]any
	if in.Data != nil {
		data = *in.Data
	}
	rendered, err := email.Render(in.Template, s.product, in.OrgName, data)
	if err != nil {
		fields["data"] = "does not fit the template"
		return api.QueueEmail400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The template could not be rendered.", Fields: &fields}}, nil
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var row store.QueueEmailRow
	err = s.cluster.Tx(ctx, in.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		suppressed, err := q.IsSuppressed(ctx, to)
		if err != nil {
			return err
		}
		state := "queued"
		if suppressed {
			state = "suppressed"
		}
		row, err = q.QueueEmail(ctx, store.QueueEmailParams{
			OrgID: in.OrgId, ID: id, ToAddress: to, Template: in.Template,
			Subject: rendered.Subject, HtmlBody: rendered.HTML, TextBody: rendered.Text,
			State: state, NextAttemptAt: time.Now().UTC(),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.QueueEmail202JSONResponse(toAPI(row.OrgID, row.ID, row.Template, row.State, row.Attempts, row.NextAttemptAt, row.SentAt, row.LastError)), nil
}

// GetEmail is one queued email's state, for a service checking delivery.
func (s *Server) GetEmail(ctx context.Context, req api.GetEmailRequestObject) (api.GetEmailResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetEmail403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a service reads the outbox."}, nil
	}
	var row store.GetEmailRow
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetEmail(ctx, store.GetEmailParams{OrgID: req.OrgId, ID: req.EmailId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetEmail404JSONResponse{Code: "email.not_found", Message: "No such email."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetEmail200JSONResponse(toAPI(row.OrgID, row.ID, row.Template, row.State, row.Attempts, row.NextAttemptAt, row.SentAt, row.LastError)), nil
}

func toAPI(orgID, id uuid.UUID, template, state string, attempts int32, next time.Time, sentAt pgtype.Timestamptz, lastError pgtype.Text) api.Email {
	e := api.Email{Id: id, OrgId: orgID, Template: template, State: api.EmailState(state), Attempts: int(attempts), NextAttemptAt: &next}
	if sentAt.Valid {
		e.SentAt = &sentAt.Time
	}
	if lastError.Valid {
		e.LastError = &lastError.String
	}
	return e
}
