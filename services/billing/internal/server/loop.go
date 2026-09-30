package server

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/store"
)

// Run is billing's own tick, hourly: the reminders a trial or a grace
// period owes, and a trial that lapsed with no one reading the plan. There
// is no scheduler; a reminder can be an hour late.
func (s *Server) Run(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("billing loop failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Tick is one pass.
func (s *Server) Tick(ctx context.Context) error {
	ctx = db.WithActor(ctx, db.SystemActor("billing"))
	var orgs []uuid.UUID
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrgsNeedingAttention(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := s.remind(ctx, org); err != nil {
			s.logger.Warn("billing reminder not handled", "org_id", org, "error", err)
		}
	}
	return nil
}

// once sends a notice unless it went already, and records that it did.
func (s *Server) once(ctx context.Context, org uuid.UUID, notice, kind string, data map[string]any) error {
	sent := false
	_, err := s.update(ctx, org, func(a *store.Account) error {
		if slices.Contains(a.Notices, notice) {
			sent = true
			return nil
		}
		a.Notices = append(a.Notices, notice)
		return nil
	})
	if err != nil || sent {
		return err
	}
	s.notify(ctx, org, notice+":"+org.String(), kind, data)
	return nil
}

func (s *Server) remind(ctx context.Context, org uuid.UUID) error {
	a, err := s.account(ctx, org) // ends a lapsed trial on the way
	if err != nil {
		return err
	}
	now := s.now()
	switch {
	case a.State == "trialing" && !a.SubscriptionRef.Valid && a.TrialEndsAt.Valid:
		left := a.TrialEndsAt.Time.Sub(now)
		if left <= 24*time.Hour {
			return s.once(ctx, org, "trial:13", "trial_ending", map[string]any{
				"heading": "Your trial ends tomorrow",
				"line":    fmt.Sprintf("Add a payment method on the billing page to keep the %s plan. Without one, the organization moves to %s: nothing is deleted, but what %s adds stops.", a.Band, plan.Lowest(), a.Band),
			})
		}
		if left <= 4*24*time.Hour {
			return s.once(ctx, org, "trial:10", "trial_ending", map[string]any{
				"heading": "Your trial ends in four days",
				"line":    fmt.Sprintf("Add a payment method on the billing page to keep the %s plan without a break.", a.Band),
			})
		}
	case a.State == "past_due" && a.GraceStartedAt.Valid:
		since := now.Sub(a.GraceStartedAt.Time)
		if since >= 12*24*time.Hour {
			return s.once(ctx, org, "dunning:12", "payment_failed", map[string]any{
				"heading": "Two days left to update your payment method",
				"line":    fmt.Sprintf("On day 14 the organization moves to the %s plan: nothing is deleted and nobody is removed, but what %s adds stops. Update the payment method on the billing page to keep the plan.", plan.Lowest(), a.Band),
			})
		}
		if since >= 7*24*time.Hour {
			return s.once(ctx, org, "dunning:7", "payment_failed", map[string]any{
				"heading": "Your payment still has not gone through",
				"line":    "We are retrying. Update the payment method on the billing page before day 14 to keep the plan.",
			})
		}
	}
	return nil
}
