package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/store"
)

func durationHours(h int) time.Duration { return time.Duration(h) * time.Hour }

// system is the context work this service does on its own runs in: its
// own actor, and no request to be cancelled with.
func system(ctx context.Context) context.Context {
	return db.WithActor(context.WithoutCancel(ctx), db.SystemActor(serviceName))
}

// EmitWebhookEvent takes an event from a service: the audit service with
// the core's membership events, a product with its own. Each subscribed
// endpoint gets a delivery row before this answers, and each is attempted
// at once, off this request's path. An org with no endpoint for the type,
// or on a plan without webhooks, is sent nothing.
func (s *Server) EmitWebhookEvent(ctx context.Context, req api.EmitWebhookEventRequestObject) (api.EmitWebhookEventResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return fail(http.StatusForbidden, httpx.CodeForbidden, "Services only.", nil), nil
	}
	in := req.Body
	org := req.OrgId.String()
	if !s.types.Known(webhook.Type(in.Type)) {
		return invalid("No such event type is registered.", map[string]string{"type": "a registered event type"}), nil
	}
	data := in.Data
	if data == nil {
		data = map[string]any{}
	}
	if err := webhook.CheckData(data); err != nil {
		return fail(http.StatusBadRequest, codePersonalData, "Event data carries ids and values, never a name or an email, and is at most 16 KB.", map[string]string{"data": err.Error()}), nil
	}
	id := uuid.Nil
	if in.Id != nil {
		id = *in.Id
	}
	if id == uuid.Nil {
		var err error
		if id, err = uuid.NewV7(); err != nil {
			return nil, err
		}
	}
	occurred := s.now()
	if in.OccurredAt != nil && !in.OccurredAt.IsZero() {
		occurred = in.OccurredAt.UTC()
	}

	var endpoints []uuid.UUID
	err := s.cluster.Read(ctx, org, func(tx pgx.Tx) error {
		var err error
		endpoints, err = store.New(tx).SubscribedEndpoints(ctx, store.SubscribedEndpointsParams{OrgID: req.OrgId, Type: in.Type})
		return err
	})
	if err != nil {
		return nil, err
	}
	accepted := api.EmitWebhookEvent202JSONResponse{Id: id, Deliveries: 0}
	if len(endpoints) == 0 {
		return accepted, nil
	}
	// The plan and its overrides, read now: a downgrade or an ended
	// override stops deliveries on the next event.
	ent, err := s.plans.Entitlements(ctx, org)
	if err != nil {
		return nil, err
	}
	if ent.CheckFeature(plan.Webhooks) != nil {
		return accepted, nil
	}
	if s.limiter != nil {
		v, err := s.limiter.Take(ctx, s.eventCap, "org:"+org)
		if err == nil && !v.Allowed {
			s.logger.Warn("webhook events over the org's cap", "org_id", org, "type", in.Type, "alert", true)
			return fail(http.StatusTooManyRequests, httpx.CodeRateLimited, "This organization is sending too many webhook events. Try again shortly.", nil), nil
		}
	}

	deliveries, err := s.record(ctx, req.OrgId, id, webhook.Type(in.Type), occurred, data, endpoints)
	if err != nil {
		return nil, err
	}
	for _, d := range deliveries {
		s.dispatch(ctx, req.OrgId, d)
	}
	accepted.Deliveries = len(deliveries)
	return accepted, nil
}

// record writes a message and a pending delivery of it to each endpoint,
// leased so the sweep leaves them to the attempt about to be made. A
// message already recorded (the same id again) records nothing.
func (s *Server) record(ctx context.Context, org, id uuid.UUID, typ webhook.Type, occurred time.Time, data map[string]any, endpoints []uuid.UUID) ([]uuid.UUID, error) {
	payload, err := json.Marshal(webhook.Payload{ID: id.String(), Type: typ, OrgID: org.String(), OccurredAt: occurred, Data: data})
	if err != nil {
		return nil, err
	}
	var out []uuid.UUID
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		n, err := q.InsertMessage(ctx, store.InsertMessageParams{OrgID: org, ID: id, Type: string(typ), OccurredAt: occurred, Payload: payload})
		if err != nil || n == 0 {
			return err
		}
		for _, e := range endpoints {
			did, err := uuid.NewV7()
			if err != nil {
				return err
			}
			if _, err := q.InsertDelivery(ctx, store.InsertDeliveryParams{OrgID: org, ID: did, MessageID: id, EndpointID: e, NextAttemptAt: at(s.now().Add(lease))}); err != nil {
				return err
			}
			out = append(out, did)
		}
		return nil
	})
	return out, err
}

// dispatch attempts a delivery off the caller's path. If the process ends
// first, the delivery is still a pending row, and the sweep sends it once
// its lease runs out.
func (s *Server) dispatch(ctx context.Context, org, delivery uuid.UUID) {
	s.inflight.Add(1)
	go func() {
		defer s.inflight.Done()
		ctx, cancel := context.WithTimeout(system(ctx), 30*time.Second)
		defer cancel()
		if _, err := s.attempt(ctx, org, delivery, false); err != nil {
			s.logger.Error("webhook attempt not recorded", "org_id", org.String(), "delivery_id", delivery.String(), "error", err)
		}
	}()
}

// errDone is a delivery that is no longer pending, found by an automatic
// attempt: someone else finished it.
var errDone = errors.New("delivery is not pending")

// attempt sends one delivery and records how it went: the attempt row, and
// the delivery succeeded, pending again after its backoff, or failed for
// good. manual is an admin's resend or test, which goes whatever the
// delivery's status.
func (s *Server) attempt(ctx context.Context, org, id uuid.UUID, manual bool) (bool, error) {
	var d store.DeliveryForAttemptRow
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		d, err = q.DeliveryForAttempt(ctx, store.DeliveryForAttemptParams{OrgID: org, ID: id})
		if err != nil {
			return err
		}
		if !manual && d.Status != "pending" {
			return errDone
		}
		if !manual && !d.Enabled {
			return q.GiveUpDelivery(ctx, store.GiveUpDeliveryParams{OrgID: org, ID: id, Error: pgtype.Text{String: "The endpoint is turned off.", Valid: true}})
		}
		return q.LeaseDelivery(ctx, store.LeaseDeliveryParams{OrgID: org, ID: id, Until: at(s.now().Add(lease))})
	})
	if errors.Is(err, errDone) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !manual && !d.Enabled {
		return false, nil
	}

	started, clock := s.now(), time.Now()
	status, problem := s.send(ctx, org, d, started)
	latency := int32(time.Since(clock).Milliseconds())
	if latency < 0 {
		latency = 0
	}
	ok := problem == ""

	next := pgtype.Timestamptz{}
	result := "succeeded"
	if !ok {
		attempts := int(d.Attempts) + 1
		if attempts >= MaxAttempts {
			result = "failed"
		} else {
			result = "pending"
			wait := Backoff[min(attempts-1, len(Backoff)-1)]
			next = at(s.now().Add(wait))
		}
	}
	code := pgtype.Int4{}
	if status > 0 {
		code = pgtype.Int4{Int32: int32(status), Valid: true}
	}
	why := pgtype.Text{}
	if problem != "" {
		why = pgtype.Text{String: problem, Valid: true}
	}
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		aid, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if err := q.InsertAttempt(ctx, store.InsertAttemptParams{OrgID: org, ID: aid, DeliveryID: id, AttemptedAt: started, Manual: manual, StatusCode: code, LatencyMs: latency, Error: why}); err != nil {
			return err
		}
		return q.FinishAttempt(ctx, store.FinishAttemptParams{OrgID: org, ID: id, Status: result, NextAttemptAt: next,
			AttemptedAt: at(started), StatusCode: code, LatencyMs: pgtype.Int4{Int32: latency, Valid: true}, Error: why})
	})
	if err != nil {
		return false, err
	}
	if !ok {
		s.logger.Warn("webhook delivery failed", "org_id", org.String(), "delivery_id", id.String(), "status", status, "result", result)
	}
	return ok, nil
}

// send makes the request: the stored body, signed now under the endpoint's
// secret and, during a rotation's overlap, the one it replaced. It answers
// the endpoint's status and, when that is not a success, why in a few
// words; never the endpoint's own answer, which is read and dropped.
func (s *Server) send(ctx context.Context, org uuid.UUID, d store.DeliveryForAttemptRow, now time.Time) (int, string) {
	keys, err := s.signingKeys(ctx, org, d, now)
	if err != nil {
		s.logger.Error("webhook secret unreadable", "org_id", org.String(), "endpoint_id", d.EndpointID.String(), "error", err)
		return 0, "The signing secret could not be read."
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Url, bytes.NewReader(d.Payload))
	if err != nil {
		return 0, "The endpoint's URL is not valid."
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.cfg.Product+"-Webhooks/1.0")
	webhook.Sign(req.Header, d.MessageID.String(), now, d.Payload, keys...)
	resp, err := s.http.Do(req)
	if err != nil {
		return 0, describe(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, answerBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Sprintf("The endpoint answered %d.", resp.StatusCode)
	}
	return resp.StatusCode, ""
}

// signingKeys is the endpoint's secret, then the one it replaced while
// that still signs.
func (s *Server) signingKeys(ctx context.Context, org uuid.UUID, d store.DeliveryForAttemptRow, now time.Time) ([][]byte, error) {
	current, err := s.keys.Decrypt(ctx, org.String(), d.Secret, secretPurpose)
	if err != nil {
		return nil, err
	}
	keys := [][]byte{current}
	if len(d.PreviousSecret) > 0 && d.PreviousExpiresAt.Valid && d.PreviousExpiresAt.Time.After(now) {
		previous, err := s.keys.Decrypt(ctx, org.String(), d.PreviousSecret, secretPurpose)
		if err != nil {
			return nil, err
		}
		keys = append(keys, previous)
	}
	return keys, nil
}

// describe is why a request did not get an answer, without the address.
func describe(err error) string {
	var netErr net.Error
	switch {
	case errors.Is(err, egress.ErrNotPublic):
		return "The endpoint's address is not public."
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "The endpoint did not answer in time."
	case errors.Is(err, envelope.ErrCannotDecrypt):
		return "The signing secret could not be read."
	}
	return "The endpoint could not be reached."
}

// Sweep attempts every delivery that is due: failed ones whose backoff has
// passed, and any whose attempt was cut short (its lease ran out). It
// claims a batch at a time, until none is left, and answers how many it
// attempted.
func (s *Server) Sweep(ctx context.Context) (int, error) {
	ctx = system(ctx)
	total := 0
	for {
		var due []store.ClaimDueDeliveriesRow
		err := s.cluster.Tx(ctx, envelope.PlatformOrg, func(tx pgx.Tx) error {
			var err error
			due, err = store.New(tx).ClaimDueDeliveries(ctx, store.ClaimDueDeliveriesParams{Now: s.now(), LeaseUntil: at(s.now().Add(lease)), Batch: sweepBatch})
			return err
		})
		if err != nil {
			return total, err
		}
		if len(due) == 0 {
			return total, nil
		}
		work := make(chan store.ClaimDueDeliveriesRow)
		done := make(chan struct{})
		for range min(sweepWorkers, len(due)) {
			go func() {
				defer func() { done <- struct{}{} }()
				for d := range work {
					actx, cancel := context.WithTimeout(ctx, 30*time.Second)
					if _, err := s.attempt(actx, d.OrgID, d.ID, false); err != nil {
						s.logger.Error("webhook retry not recorded", "org_id", d.OrgID.String(), "delivery_id", d.ID.String(), "error", err)
					}
					cancel()
				}
			}()
		}
		for _, d := range due {
			work <- d
		}
		close(work)
		for range min(sweepWorkers, len(due)) {
			<-done
		}
		total += len(due)
		if len(due) < sweepBatch || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

// Housekeeping is the daily pass: the retry sweep, rotated-out secrets
// forgotten once their overlap ends, and events past retention deleted
// with their deliveries.
func (s *Server) Housekeeping(ctx context.Context) error {
	sent, err := s.Sweep(ctx)
	if err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	ctx = system(ctx)
	var ended, expired int64
	err = s.cluster.Tx(ctx, envelope.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if ended, err = q.EndExpiredSecrets(ctx, s.now()); err != nil {
			return err
		}
		expired, err = q.DeleteMessagesBefore(ctx, s.now().Add(-Retention))
		return err
	})
	if err != nil {
		return err
	}
	s.logger.Info("webhooks housekeeping", "retried", sent, "secrets_ended", ended, "events_expired", expired)
	return nil
}
