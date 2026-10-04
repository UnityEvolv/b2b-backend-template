package server

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/store"
)

const (
	defaultPage = 50
	maxPage     = 200
)

// ListWebhookDeliveries is the org's deliveries, newest first, a page at a
// time, optionally for one endpoint or in one status.
func (s *Server) ListWebhookDeliveries(ctx context.Context, req api.ListWebhookDeliveriesRequestObject) (api.ListWebhookDeliveriesResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	p := req.Params
	size := httpx.PageSize(p.Limit, defaultPage, maxPage)
	params := store.ListDeliveriesParams{OrgID: req.OrgId, PageSize: int32(size + 1)}
	if p.EndpointId != nil {
		params.EndpointID = pgtype.UUID{Bytes: *p.EndpointId, Valid: true}
	}
	if p.Status != nil {
		switch *p.Status {
		case api.Pending, api.Succeeded, api.Failed:
			params.Status = pgtype.Text{String: string(*p.Status), Valid: true}
		default:
			return invalid("The status is not valid.", map[string]string{"status": "pending, succeeded or failed"}), nil
		}
	}
	if p.Cursor != nil {
		c, ok, err := httpx.DecodeCursor(*p.Cursor)
		if err != nil {
			return invalid("The cursor is not valid.", map[string]string{"cursor": "from the previous page's next_cursor"}), nil
		}
		if ok {
			params.BeforeAt = at(c.At)
			params.BeforeID = pgtype.UUID{Bytes: c.ID, Valid: true}
		}
	}
	var rows []store.ListDeliveriesRow
	err := s.cluster.Read(ctx, org, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListDeliveries(ctx, params)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.DeliveryPage{Deliveries: []api.Delivery{}}
	if len(rows) > size {
		last := rows[size-1]
		next := httpx.Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
		out.NextCursor = &next
		rows = rows[:size]
	}
	for _, r := range rows {
		out.Deliveries = append(out.Deliveries, toDelivery(store.Delivery{
			OrgID: r.OrgID, ID: r.ID, MessageID: r.MessageID, EndpointID: r.EndpointID, Status: r.Status, Attempts: r.Attempts,
			NextAttemptAt: r.NextAttemptAt, LastAttemptAt: r.LastAttemptAt, LastStatusCode: r.LastStatusCode,
			LastLatencyMs: r.LastLatencyMs, LastError: r.LastError, CreatedAt: r.CreatedAt,
		}, r.EventType))
	}
	return api.ListWebhookDeliveries200JSONResponse(out), nil
}

// GetWebhookDelivery is one delivery, its body and every attempt.
func (s *Server) GetWebhookDelivery(ctx context.Context, req api.GetWebhookDeliveryRequestObject) (api.GetWebhookDeliveryResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	d, err := s.detail(ctx, req.OrgId, req.DeliveryId)
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("delivery"), nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetWebhookDelivery200JSONResponse(d), nil
}

// ResendWebhookDelivery attempts a delivery again now, as the same message
// with the same webhook-id, and answers with how it went. On a plan with
// webhooks only.
func (s *Server) ResendWebhookDelivery(ctx context.Context, req api.ResendWebhookDeliveryRequestObject) (api.ResendWebhookDeliveryResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	if _, err := s.detail(ctx, req.OrgId, req.DeliveryId); errors.Is(err, pgx.ErrNoRows) {
		return notFound("delivery"), nil
	} else if err != nil {
		return nil, err
	}
	if f, err := s.onPlan(ctx, org); f != nil || err != nil {
		return f, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org, Action: "webhooks.delivery.resent", TargetType: "webhook_delivery", TargetID: req.DeliveryId.String()}); err != nil {
		return nil, err
	}
	if _, err := s.attempt(system(ctx), req.OrgId, req.DeliveryId, true); err != nil {
		return nil, err
	}
	d, err := s.detail(ctx, req.OrgId, req.DeliveryId)
	if err != nil {
		return nil, err
	}
	return api.ResendWebhookDelivery200JSONResponse(d), nil
}

// SendWebhookTest sends a webhook.test event to one endpoint now, whatever
// it subscribes to, and answers with how it went. It is a delivery like any
// other: listed, retried if it fails, resendable.
func (s *Server) SendWebhookTest(ctx context.Context, req api.SendWebhookTestRequestObject) (api.SendWebhookTestResponseObject, error) {
	org := req.OrgId.String()
	if f, err := s.allowed(ctx, org); f != nil || err != nil {
		return f, err
	}
	if _, err := s.endpoint(ctx, req.OrgId, req.EndpointId); errors.Is(err, pgx.ErrNoRows) {
		return notFound("endpoint"), nil
	} else if err != nil {
		return nil, err
	}
	if f, err := s.onPlan(ctx, org); f != nil || err != nil {
		return f, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org, Action: "webhooks.endpoint.tested", TargetType: "webhook_endpoint", TargetID: req.EndpointId.String()}); err != nil {
		return nil, err
	}
	deliveries, err := s.record(ctx, req.OrgId, id, webhook.Test, s.now(), map[string]any{"endpoint_id": req.EndpointId.String()}, []uuid.UUID{req.EndpointId})
	if err != nil {
		return nil, err
	}
	if len(deliveries) != 1 {
		return nil, errors.New("webhooks: test delivery not recorded")
	}
	if _, err := s.attempt(system(ctx), req.OrgId, deliveries[0], true); err != nil {
		return nil, err
	}
	d, err := s.detail(ctx, req.OrgId, deliveries[0])
	if err != nil {
		return nil, err
	}
	return api.SendWebhookTest200JSONResponse(d), nil
}

// detail is a delivery with its body and every attempt.
func (s *Server) detail(ctx context.Context, org, id uuid.UUID) (api.DeliveryDetail, error) {
	var row store.GetDeliveryRow
	var attempts []store.Attempt
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if row, err = q.GetDelivery(ctx, store.GetDeliveryParams{OrgID: org, ID: id}); err != nil {
			return err
		}
		attempts, err = q.ListAttempts(ctx, store.ListAttemptsParams{OrgID: org, DeliveryID: id})
		return err
	})
	if err != nil {
		return api.DeliveryDetail{}, err
	}
	d := toDelivery(store.Delivery{
		OrgID: row.OrgID, ID: row.ID, MessageID: row.MessageID, EndpointID: row.EndpointID, Status: row.Status, Attempts: row.Attempts,
		NextAttemptAt: row.NextAttemptAt, LastAttemptAt: row.LastAttemptAt, LastStatusCode: row.LastStatusCode,
		LastLatencyMs: row.LastLatencyMs, LastError: row.LastError, CreatedAt: row.CreatedAt,
	}, row.EventType)
	out := api.DeliveryDetail{
		Id: d.Id, EndpointId: d.EndpointId, MessageId: d.MessageId, EventType: d.EventType, Status: d.Status, Attempts: d.Attempts,
		NextAttemptAt: d.NextAttemptAt, LastAttemptAt: d.LastAttemptAt, LastStatusCode: d.LastStatusCode, LastLatencyMs: d.LastLatencyMs,
		LastError: d.LastError, CreatedAt: d.CreatedAt, Payload: map[string]any{}, AttemptLog: []api.Attempt{},
	}
	if err := json.Unmarshal(row.Payload, &out.Payload); err != nil {
		return api.DeliveryDetail{}, err
	}
	for _, a := range attempts {
		out.AttemptLog = append(out.AttemptLog, api.Attempt{
			Id: a.ID, AttemptedAt: a.AttemptedAt.UTC(), Manual: a.Manual, StatusCode: int4(a.StatusCode), LatencyMs: int(a.LatencyMs), Error: text(a.Error),
		})
	}
	return out, nil
}

func toDelivery(d store.Delivery, eventType string) api.Delivery {
	return api.Delivery{
		Id: d.ID, EndpointId: d.EndpointID, MessageId: d.MessageID, EventType: eventType, Status: api.DeliveryStatus(d.Status),
		Attempts: int(d.Attempts), NextAttemptAt: ts(d.NextAttemptAt), LastAttemptAt: ts(d.LastAttemptAt),
		LastStatusCode: int4(d.LastStatusCode), LastLatencyMs: int4(d.LastLatencyMs), LastError: text(d.LastError), CreatedAt: d.CreatedAt.UTC(),
	}
}
