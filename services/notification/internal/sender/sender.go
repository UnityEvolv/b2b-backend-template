// Package sender is the outbox's delivery loop: claim what is due, send it,
// record the outcome, and try again later on a transient failure. It runs
// inside the notification service; there is no scheduler and no queue.
package sender

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email/transport"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Backoff is how long to wait before each retry. After the last entry the
// email is failed and error tracking sees it.
var Backoff = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, time.Hour, 6 * time.Hour}

// Sender delivers the outbox.
type Sender struct {
	cluster   *db.Cluster
	transport transport.Transport
	from      string
	logger    *slog.Logger
	backoff   []time.Duration
	batch     int32
}

// New is a sender delivering through t, as from.
func New(cluster *db.Cluster, t transport.Transport, from string, logger *slog.Logger) *Sender {
	return &Sender{cluster: cluster, transport: t, from: from, logger: logger, backoff: Backoff, batch: 50}
}

// WithBackoff replaces the retry schedule, for tests.
func (s *Sender) WithBackoff(b []time.Duration) *Sender { s.backoff = b; return s }

// Run delivers until ctx ends, polling every interval and draining what is
// due. Two nodes can run it at once: claiming locks rows.
func (s *Sender) Run(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		for {
			n, err := s.Deliver(ctx)
			if err != nil {
				s.logger.Error("outbox pass failed", "error", err)
				break
			}
			if n < int(s.batch) {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Deliver sends one batch of due emails and reports how many it claimed.
func (s *Sender) Deliver(ctx context.Context) (int, error) {
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	var due []store.ClaimDueEmailsRow
	err := s.cluster.Tx(ctx, envelope.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		due, err = store.New(tx).ClaimDueEmails(ctx, s.batch)
		return err
	})
	if err != nil {
		return 0, err
	}
	for _, m := range due {
		s.deliverOne(ctx, m)
	}
	return len(due), nil
}

func (s *Sender) deliverOne(ctx context.Context, m store.ClaimDueEmailsRow) {
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	providerID, err := s.transport.Send(sendCtx, transport.Outgoing{
		From: s.from, To: m.ToAddress, Subject: m.Subject, HTML: m.HtmlBody, Text: m.TextBody,
		Tags:        map[string]string{"org_id": m.OrgID.String(), "email_id": m.ID.String()},
		Unsubscribe: m.UnsubscribeUrl.String,
	})
	cancel()

	// Never the address in a log: the email id is enough to find it.
	fields := []any{"email_id", m.ID.String(), "org_id", m.OrgID.String(), "attempt", m.Attempts + 1}
	switch {
	case err == nil:
		s.record(ctx, m, func(q *store.Queries) error {
			return q.MarkEmailSent(ctx, store.MarkEmailSentParams{OrgID: m.OrgID, ID: m.ID, ProviderMessageID: pgtype.Text{String: providerID, Valid: true}})
		})
	case transport.IsPermanent(err) || int(m.Attempts) >= len(s.backoff):
		s.logger.Error("email failed", append(fields, "error", err)...)
		s.record(ctx, m, func(q *store.Queries) error {
			return q.MarkEmailFailed(ctx, store.MarkEmailFailedParams{OrgID: m.OrgID, ID: m.ID, State: "failed", LastError: pgtype.Text{String: err.Error(), Valid: true}})
		})
	default:
		wait := s.backoff[m.Attempts]
		s.logger.Warn("email send failed, will retry", append(fields, "retry_in", wait.String(), "error", err)...)
		s.record(ctx, m, func(q *store.Queries) error {
			return q.MarkEmailRetry(ctx, store.MarkEmailRetryParams{OrgID: m.OrgID, ID: m.ID, NextAttemptAt: time.Now().UTC().Add(wait), LastError: pgtype.Text{String: err.Error(), Valid: true}})
		})
	}
}

func (s *Sender) record(ctx context.Context, m store.ClaimDueEmailsRow, fn func(*store.Queries) error) {
	if err := s.cluster.Tx(ctx, m.OrgID.String(), func(tx pgx.Tx) error { return fn(store.New(tx)) }); err != nil {
		s.logger.Error("outbox update failed", "email_id", m.ID.String(), "error", err)
	}
}
