// Package server implements the audit API: an append-only record that
// services write through and an org's admins read.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/store"
)

// Server answers the audit API.
type Server struct {
	cluster *db.Cluster
	logger  *slog.Logger
	authz   authz.Checker
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API on cluster. checker says who in an org may read its log:
// the audit permission, Owners and Admins by default.
func New(cluster *db.Cluster, logger *slog.Logger, checker authz.Checker) *Server {
	return &Server{cluster: cluster, logger: logger, authz: checker}
}

// Limits is this API's rate limits, one line per endpoint. Recording is done
// by services, which are not limited; reading is a per-membership read.
var Limits = map[string]ratelimit.Bound{
	"GET /v1/organizations/{org_id}/audit-events":        ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/audit-events/export": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	// The organization service's data endpoints (UO-183, UO-184).
	"GET /v1/internal/organizations/{org_id}/data":          ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/internal/organizations/{org_id}/data":       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/internal/users/{user_id}/data":                 ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"POST /v1/internal/organizations/{org_id}/audit/expire": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
}

// Handler is the API's routes, with bad requests and failures answered in the
// error envelope. middlewares run after routing, per endpoint.
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

var (
	actionShape = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	actorShape  = regexp.MustCompile(`^(membership|user):[0-9a-f-]{36}$|^system:[a-z][a-z0-9-]*$`)
)

const (
	maxDetails    = 8 * 1024
	defaultPage   = 50
	maxPage       = 200
	maxTextLength = 200
)

// RecordAuditEvent appends one entry. Services only: a person never writes
// the audit log directly, the service handling their action does.
func (s *Server) RecordAuditEvent(ctx context.Context, req api.RecordAuditEventRequestObject) (api.RecordAuditEventResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.RecordAuditEvent403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a service records audit entries."}, nil
	}
	in := req.Body
	fields := map[string]string{}
	if !actionShape.MatchString(in.Action) {
		fields["action"] = "dotted, lower case, such as organization.plan.changed"
	}
	if !actorShape.MatchString(in.Actor) {
		fields["actor"] = "membership:<uuid>, user:<uuid> or system:<service>"
	}
	if strings.TrimSpace(in.TargetType) == "" || len(in.TargetType) > maxTextLength {
		fields["target_type"] = "required, at most 200 characters"
	}
	if strings.TrimSpace(in.TargetId) == "" || len(in.TargetId) > maxTextLength {
		fields["target_id"] = "required, at most 200 characters"
	}
	details := []byte("{}")
	if in.Details != nil {
		b, err := json.Marshal(in.Details)
		if err != nil || len(b) > maxDetails {
			fields["details"] = "a small JSON object, at most 8 KB"
		} else {
			details = b
		}
	}
	var ip *netip.Addr
	if in.SourceIp != nil && *in.SourceIp != "" {
		addr, err := netip.ParseAddr(*in.SourceIp)
		if err != nil {
			fields["source_ip"] = "an IP address"
		} else {
			ip = &addr
		}
	}
	if len(fields) > 0 {
		return api.RecordAuditEvent400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}

	occurred := time.Now().UTC()
	if in.OccurredAt != nil && !in.OccurredAt.IsZero() {
		occurred = in.OccurredAt.UTC()
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	params := store.RecordAuditEventParams{
		OrgID:      in.OrgId,
		ID:         id,
		OccurredAt: occurred,
		Actor:      in.Actor,
		Action:     in.Action,
		TargetType: in.TargetType,
		TargetID:   in.TargetId,
		SourceIp:   ip,
		Details:    details,
	}
	if in.RequestId != nil && *in.RequestId != "" {
		params.RequestID = pgtype.Text{String: *in.RequestId, Valid: true}
	}

	var row store.RecordAuditEventRow
	err = s.cluster.Tx(ctx, in.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).RecordAuditEvent(ctx, params)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.RecordAuditEvent201JSONResponse(toAPI(row.OrgID, row.ID, row.OccurredAt, row.Actor, row.Action, row.TargetType, row.TargetID, row.SourceIp, row.RequestID, row.Details)), nil
}

func toAPI(orgID, id uuid.UUID, at time.Time, actor, action, targetType, targetID string, ip *netip.Addr, requestID pgtype.Text, details []byte) api.AuditEvent {
	ev := api.AuditEvent{
		Id: id, OrgId: orgID, OccurredAt: at, Actor: actor, Action: action,
		TargetType: targetType, TargetId: targetID, Details: map[string]interface{}{},
	}
	_ = json.Unmarshal(details, &ev.Details)
	if ip != nil {
		s := ip.String()
		ev.SourceIp = &s
	}
	if requestID.Valid {
		ev.RequestId = &requestID.String
	}
	return ev
}
