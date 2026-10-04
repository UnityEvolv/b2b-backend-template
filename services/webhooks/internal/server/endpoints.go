package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/store"
)

// ListWebhookEventTypes is what an endpoint may subscribe to, and whether
// the org's plan has webhooks now: what the admin page needs to draw.
func (s *Server) ListWebhookEventTypes(ctx context.Context, req api.ListWebhookEventTypesRequestObject) (api.ListWebhookEventTypesResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	out := api.EventTypeList{Available: true, EventTypes: []api.EventType{}}
	for _, t := range s.types.Types() {
		out.EventTypes = append(out.EventTypes, api.EventType{Type: string(t.Type), Description: t.Description})
	}
	ent, err := s.plans.Entitlements(ctx, org)
	if err != nil {
		return nil, err
	}
	if err := ent.CheckFeature(plan.Webhooks); err != nil {
		out.Available = false
		if r, ok := plan.AsRefusal(err); ok && r.Required != "" {
			required := string(r.Required)
			out.RequiredPlan = &required
		}
	}
	return api.ListWebhookEventTypes200JSONResponse(out), nil
}

// ListWebhookEndpoints is every endpoint of the org, without its secret.
func (s *Server) ListWebhookEndpoints(ctx context.Context, req api.ListWebhookEndpointsRequestObject) (api.ListWebhookEndpointsResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	var rows []store.Endpoint
	err := s.cluster.Read(ctx, org, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListEndpoints(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]api.Endpoint, 0, len(rows))
	for _, e := range rows {
		out = append(out, toEndpoint(e))
	}
	return api.ListWebhookEndpoints200JSONResponse{Endpoints: out}, nil
}

// CreateWebhookEndpoint adds an endpoint with a fresh signing secret,
// sealed under the org's key and shown in this answer only.
func (s *Server) CreateWebhookEndpoint(ctx context.Context, req api.CreateWebhookEndpointRequestObject) (api.CreateWebhookEndpointResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	in := req.Body
	fields := map[string]string{}
	target, msg := s.checkURL(ctx, in.Url)
	if msg != "" {
		fields["url"] = msg
	}
	description := ""
	if in.Description != nil {
		description = strings.TrimSpace(*in.Description)
		if len(description) > 500 {
			fields["description"] = "at most 500 characters"
		}
	}
	types, msg := s.checkTypes(in.EventTypes)
	if msg != "" {
		fields["event_types"] = msg
	}
	if len(fields) > 0 {
		return invalid("Some fields are not valid.", fields), nil
	}
	if f, err := s.onPlan(ctx, org); f != nil || err != nil {
		return f, err
	}
	enabled := in.Enabled == nil || *in.Enabled

	key, shown, err := webhook.NewSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := s.keys.Encrypt(ctx, org, key, secretPurpose)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var row store.Endpoint
	full := false
	err = s.cluster.Tx(ctx, org, func(tx pgx.Tx) error {
		q := store.New(tx)
		n, err := q.CountEndpoints(ctx, req.OrgId)
		if err != nil {
			return err
		}
		if n >= MaxEndpoints {
			full = true
			return nil
		}
		row, err = q.CreateEndpoint(ctx, store.CreateEndpointParams{
			OrgID: req.OrgId, ID: id, Url: target, Description: description, EventTypes: types, Enabled: enabled, Secret: sealed,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if full {
		return fail(http.StatusConflict, codeEndpointLimit, "An organization may have at most 20 webhook endpoints.", nil), nil
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org, Action: "webhooks.endpoint.created", TargetType: "webhook_endpoint", TargetID: id.String(),
		Details: map[string]any{"event_types": types, "enabled": enabled}}); err != nil {
		return nil, err
	}
	return api.CreateWebhookEndpoint201JSONResponse{Endpoint: toEndpoint(row), Secret: shown}, nil
}

// GetWebhookEndpoint is one endpoint, without its secret.
func (s *Server) GetWebhookEndpoint(ctx context.Context, req api.GetWebhookEndpointRequestObject) (api.GetWebhookEndpointResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	e, err := s.endpoint(ctx, req.OrgId, req.EndpointId)
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("endpoint"), nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetWebhookEndpoint200JSONResponse(toEndpoint(e)), nil
}

func (s *Server) endpoint(ctx context.Context, org, id uuid.UUID) (store.Endpoint, error) {
	var e store.Endpoint
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		e, err = store.New(tx).GetEndpoint(ctx, store.GetEndpointParams{OrgID: org, ID: id})
		return err
	})
	return e, err
}

// UpdateWebhookEndpoint changes what is given and keeps the rest. Allowed
// on any plan, so an org that lost webhooks can still turn its endpoints
// off or tidy them.
func (s *Server) UpdateWebhookEndpoint(ctx context.Context, req api.UpdateWebhookEndpointRequestObject) (api.UpdateWebhookEndpointResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	in := req.Body
	fields := map[string]string{}
	var target string
	if in.Url != nil {
		var msg string
		if target, msg = s.checkURL(ctx, *in.Url); msg != "" {
			fields["url"] = msg
		}
	}
	if in.Description != nil && len(strings.TrimSpace(*in.Description)) > 500 {
		fields["description"] = "at most 500 characters"
	}
	var types []string
	if in.EventTypes != nil {
		var msg string
		if types, msg = s.checkTypes(in.EventTypes); msg != "" {
			fields["event_types"] = msg
		}
	}
	if len(fields) > 0 {
		return invalid("Some fields are not valid.", fields), nil
	}
	var row store.Endpoint
	err := s.cluster.Tx(ctx, org, func(tx pgx.Tx) error {
		q := store.New(tx)
		e, err := q.GetEndpoint(ctx, store.GetEndpointParams{OrgID: req.OrgId, ID: req.EndpointId})
		if err != nil {
			return err
		}
		p := store.UpdateEndpointParams{OrgID: e.OrgID, ID: e.ID, Url: e.Url, Description: e.Description, EventTypes: e.EventTypes, Enabled: e.Enabled}
		if in.Url != nil {
			p.Url = target
		}
		if in.Description != nil {
			p.Description = strings.TrimSpace(*in.Description)
		}
		if in.EventTypes != nil {
			p.EventTypes = types
		}
		if in.Enabled != nil {
			p.Enabled = *in.Enabled
		}
		row, err = q.UpdateEndpoint(ctx, p)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("endpoint"), nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org, Action: "webhooks.endpoint.updated", TargetType: "webhook_endpoint", TargetID: row.ID.String(),
		Details: map[string]any{"url_changed": in.Url != nil, "event_types": row.EventTypes, "enabled": row.Enabled}}); err != nil {
		return nil, err
	}
	return api.UpdateWebhookEndpoint200JSONResponse(toEndpoint(row)), nil
}

// DeleteWebhookEndpoint removes an endpoint and its deliveries.
func (s *Server) DeleteWebhookEndpoint(ctx context.Context, req api.DeleteWebhookEndpointRequestObject) (api.DeleteWebhookEndpointResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	var n int64
	err := s.cluster.Tx(ctx, org, func(tx pgx.Tx) error {
		var err error
		n, err = store.New(tx).DeleteEndpoint(ctx, store.DeleteEndpointParams{OrgID: req.OrgId, ID: req.EndpointId})
		return err
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return notFound("endpoint"), nil
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org, Action: "webhooks.endpoint.deleted", TargetType: "webhook_endpoint", TargetID: req.EndpointId.String()}); err != nil {
		return nil, err
	}
	return api.DeleteWebhookEndpoint204Response{}, nil
}

// RotateWebhookSecret gives an endpoint a new secret, shown in this answer
// only. The old one keeps signing beside it for the overlap, so every
// delivery in that time carries both signatures and a receiver switches
// when it is ready. A rotation during an overlap ends the oldest at once:
// there are never more than two.
func (s *Server) RotateWebhookSecret(ctx context.Context, req api.RotateWebhookSecretRequestObject) (api.RotateWebhookSecretResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	overlap := defaultOverlap
	if req.Body != nil && req.Body.OverlapHours != nil {
		h := *req.Body.OverlapHours
		if h < 0 || h > int(maxOverlap.Hours()) {
			return invalid("The overlap is not valid.", map[string]string{"overlap_hours": "0 to 168"}), nil
		}
		overlap = durationHours(h)
	}
	key, shown, err := webhook.NewSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := s.keys.Encrypt(ctx, org, key, secretPurpose)
	if err != nil {
		return nil, err
	}
	var row store.Endpoint
	err = s.cluster.Tx(ctx, org, func(tx pgx.Tx) error {
		q := store.New(tx)
		e, err := q.GetEndpoint(ctx, store.GetEndpointParams{OrgID: req.OrgId, ID: req.EndpointId})
		if err != nil {
			return err
		}
		p := store.RotateEndpointSecretParams{OrgID: e.OrgID, ID: e.ID, Secret: sealed}
		if overlap > 0 {
			p.PreviousSecret = e.Secret
			p.PreviousExpiresAt = at(s.now().Add(overlap))
		}
		row, err = q.RotateEndpointSecret(ctx, p)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("endpoint"), nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org, Action: "webhooks.endpoint.secret_rotated", TargetType: "webhook_endpoint", TargetID: row.ID.String(),
		Details: map[string]any{"overlap_hours": int(overlap.Hours())}}); err != nil {
		return nil, err
	}
	return api.RotateWebhookSecret200JSONResponse{Endpoint: toEndpoint(row), Secret: shown}, nil
}

// checkURL is the URL as stored, or why it is refused: https only, no
// credentials or fragment, on a host that is not, and does not resolve
// to, a private address. Locally http and private hosts are allowed.
func (s *Server) checkURL(ctx context.Context, raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	switch {
	case err != nil || raw == "" || len(raw) > 2048 || u.Host == "" || u.Opaque != "":
		return "", "an absolute https URL, at most 2048 characters"
	case u.Scheme != "https" && !(s.cfg.Local && u.Scheme == "http"):
		return "", "https only"
	case u.User != nil:
		return "", "no user name or password in the URL"
	case u.Fragment != "":
		return "", "no #fragment"
	}
	if !s.cfg.Local {
		if err := egress.CheckHost(ctx, s.resolver, u.Hostname()); err != nil {
			return "", "a public address; this one is private, local or reserved"
		}
	}
	return u.String(), ""
}

// checkTypes is the event types an endpoint asks for, each registered,
// without repeats; nil or empty is every type.
func (s *Server) checkTypes(in *[]string) ([]string, string) {
	out := []string{}
	if in == nil {
		return out, ""
	}
	for _, t := range *in {
		t = strings.TrimSpace(t)
		if !s.types.Known(webhook.Type(t)) {
			return nil, "not a registered event type: " + t
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out, ""
}

func toEndpoint(e store.Endpoint) api.Endpoint {
	out := api.Endpoint{
		Id: e.ID, OrgId: e.OrgID, Url: e.Url, Description: e.Description, EventTypes: e.EventTypes, Enabled: e.Enabled,
		SecretRotatedAt: ts(e.SecretRotatedAt), PreviousSecretExpiresAt: ts(e.PreviousExpiresAt),
		CreatedAt: e.CreatedAt.UTC(), LastModifiedAt: e.LastModifiedAt.UTC(),
	}
	if out.EventTypes == nil {
		out.EventTypes = []string{}
	}
	return out
}
