package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/provider"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/store"
)

// maxWebhook is the largest webhook body read.
const maxWebhook = 1 << 20

// Webhook is the provider's webhook endpoint: signature verified, each event
// applied once, and anything uncertain reconciled from the event's own
// snapshot of the subscription, which the provider sends whole.
func (s *Server) Webhook(w http.ResponseWriter, r *http.Request) {
	if s.provider == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, codeNoProvider, "Payments are not set up here.")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxWebhook))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The body could not be read.")
		return
	}
	ev, err := s.provider.Verify(payload, r.Header.Get("Stripe-Signature"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "webhook.signature", "The signature does not verify.")
		return
	}
	if err := s.HandleEvent(r.Context(), ev); err != nil {
		// Never the payload: it carries billing details.
		errtrack.Capture(r.Context(), fmt.Errorf("webhook %s: %w", ev.Type, err))
		s.logger.Error("webhook not applied", "event_type", ev.Type, "error", err)
		httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Not applied; retry.")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleEvent applies one verified event, once.
func (s *Server) HandleEvent(ctx context.Context, ev provider.Event) error {
	ctx = db.WithActor(ctx, db.SystemActor("billing"))
	if ev.Type == "" || ev.Customer == "" {
		return nil
	}
	var fresh int64
	var org uuid.UUID
	err := s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if fresh, err = q.MarkEvent(ctx, store.MarkEventParams{Provider: s.provider.Name(), EventID: ev.ID}); err != nil || fresh == 0 {
			return err
		}
		org, err = q.OrgOfCustomer(ctx, pgtype.Text{String: ev.Customer, Valid: true})
		if errors.Is(err, pgx.ErrNoRows) {
			// Not one of ours: a customer made elsewhere on the account.
			org = uuid.Nil
			return nil
		}
		return err
	})
	if err != nil || fresh == 0 || org == uuid.Nil {
		return err
	}
	if err := s.apply(ctx, org, ev); err != nil {
		_ = s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
			return store.New(tx).ForgetEvent(ctx, store.ForgetEventParams{Provider: s.provider.Name(), EventID: ev.ID})
		})
		return err
	}
	return nil
}

func (s *Server) apply(ctx context.Context, org uuid.UUID, ev provider.Event) error {
	switch ev.Type {
	case provider.EventPaymentMethodAdded:
		return s.cardAdded(ctx, org, ev.Customer, ev.SetupRef)
	case provider.EventSubscriptionUpdated:
		return s.subscriptionUpdated(ctx, org, *ev.Subscription)
	case provider.EventSubscriptionDeleted:
		return s.subscriptionEnded(ctx, org)
	case provider.EventPaymentFailed:
		return s.paymentFailed(ctx, org, ev.Reason)
	case provider.EventPaymentSucceeded:
		return s.paymentSucceeded(ctx, org)
	}
	return nil
}

// cardAdded keeps the new method's brand and last four, turns automatic
// upgrade on the first time a card is added (the billing page says so, with
// the opt-out beside it), and starts the subscription a trial was waiting on.
func (s *Server) cardAdded(ctx context.Context, org uuid.UUID, customer, setupRef string) error {
	card, err := s.provider.CompleteSetup(ctx, customer, setupRef)
	if err != nil {
		return err
	}
	a, err := s.update(ctx, org, func(a *store.Account) error {
		if !a.CardLast4.Valid && a.State != "invoiced" {
			a.AutoUpgrade = true
		}
		a.CardBrand, a.CardLast4 = text(card.Brand), text(card.Last4)
		return nil
	})
	if err != nil {
		return err
	}
	if a.State == "trialing" && !a.SubscriptionRef.Valid {
		if _, err := s.changeUp(ctx, org, a, plan.Band(a.Band), "subscription"); err != nil && !errors.Is(err, provider.ErrRefused) {
			return err
		}
	}
	return nil
}

// subscriptionUpdated makes the account match the provider's subscription.
func (s *Server) subscriptionUpdated(ctx context.Context, org uuid.UUID, sub provider.Subscription) error {
	var before store.Account
	a, err := s.update(ctx, org, func(a *store.Account) error {
		before = *a
		if a.State == "invoiced" {
			return nil
		}
		a.SubscriptionRef, a.PeriodEnd = text(sub.Ref), stamp(sub.PeriodEnd)
		if sub.Band != "" {
			a.Band = string(sub.Band)
		}
		switch sub.State {
		case "past_due":
			a.State = "past_due"
			if !a.GraceStartedAt.Valid {
				a.GraceStartedAt = stamp(s.now())
			}
		case "trialing":
			a.State = "trialing"
		case "active":
			if a.State != "past_due" {
				a.State = "active"
			}
		}
		if sub.ScheduleRef == "" {
			a.ScheduleRef, a.PendingBand = pgtype.Text{}, pgtype.Text{}
		} else {
			a.ScheduleRef = text(sub.ScheduleRef)
			if sub.PendingBand != "" {
				a.PendingBand = text(string(sub.PendingBand))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if a.Band != before.Band && a.State != "invoiced" {
		reason := "subscription"
		if plan.Rank(plan.Band(a.Band)) < plan.Rank(plan.Band(before.Band)) {
			reason = "downgrade"
		}
		return s.setPlan(ctx, org, plan.Band(a.Band), reason)
	}
	return nil
}

// subscriptionEnded is the provider having cancelled: after the grace with
// no payment, or a scheduled move to free. The org drops to free; nothing
// is deleted and nobody removed.
func (s *Server) subscriptionEnded(ctx context.Context, org uuid.UUID) error {
	var before store.Account
	_, err := s.update(ctx, org, func(a *store.Account) error {
		before = *a
		if a.State == "invoiced" {
			return nil
		}
		a.State, a.Band = "free", string(plan.Free)
		a.SubscriptionRef, a.ScheduleRef, a.PendingBand, a.PeriodEnd, a.GraceStartedAt = pgtype.Text{}, pgtype.Text{}, pgtype.Text{}, pgtype.Timestamptz{}, pgtype.Timestamptz{}
		a.Notices = slices.DeleteFunc(a.Notices, func(n string) bool { return strings.HasPrefix(n, "dunning:") })
		return nil
	})
	if err != nil || before.State == "invoiced" || before.Band == string(plan.Free) {
		return err
	}
	reason, heading := "downgrade", "Your organization is on the free plan now"
	if before.State == "past_due" {
		reason, heading = "payment_failure", "Payment did not go through, so your organization is on the free plan"
	}
	if err := s.setPlan(ctx, org, plan.Free, reason); err != nil {
		return err
	}
	s.notify(ctx, org, "ended:"+org.String()+":"+s.now().Format("2006-01-02"), "downgraded", s.checklist(plan.Band(before.Band), plan.Free,
		heading, "Nothing was deleted and nobody was removed. Add a payment method on the billing page to start a subscription again."))
	return nil
}

// paymentFailed starts the grace: past due from the first failure, the
// provider retrying on its own schedule.
func (s *Server) paymentFailed(ctx context.Context, org uuid.UUID, reason string) error {
	first := false
	a, err := s.update(ctx, org, func(a *store.Account) error {
		if a.State == "invoiced" {
			return nil
		}
		if !a.GraceStartedAt.Valid {
			a.GraceStartedAt, first = stamp(s.now()), true
		}
		a.State = "past_due"
		return nil
	})
	if err != nil || !first {
		return err
	}
	s.notify(ctx, org, "dunning:first:"+org.String()+":"+a.GraceStartedAt.Time.Format(time.RFC3339), "payment_failed", map[string]any{
		"heading": "A payment for your plan did not go through",
		"line":    reason + " We will retry over the next 14 days. Update the payment method on the billing page to keep the plan.",
	})
	return nil
}

// paymentSucceeded clears a past-due account with one recovery email.
func (s *Server) paymentSucceeded(ctx context.Context, org uuid.UUID) error {
	was := false
	_, err := s.update(ctx, org, func(a *store.Account) error {
		if a.State != "past_due" {
			return nil
		}
		was = true
		a.State, a.GraceStartedAt = "active", pgtype.Timestamptz{}
		a.Notices = slices.DeleteFunc(a.Notices, func(n string) bool { return strings.HasPrefix(n, "dunning:") })
		return nil
	})
	if err != nil || !was {
		return err
	}
	s.notify(ctx, org, "recovered:"+org.String()+":"+s.now().Format(time.RFC3339), "payment_recovered", map[string]any{
		"heading": "Your payment went through", "line": "Your plan carries on as before. Thank you.",
	})
	return nil
}
