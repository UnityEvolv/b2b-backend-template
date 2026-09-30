// Package provider is the payment provider behind billing: Stripe
// first, Razorpay later behind the same interface. Nothing here assumes one
// provider's object model; each implementation maps its own to these.
package provider

import (
	"context"
	"errors"
	"time"
)

// Band is a plan band the provider sells, by its name in the plan registry,
// such as team.
type Band string

// Price is what a band costs per period, in minor units.
type Price struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Interval string `json:"interval"`
}

// Card is what we keep of a payment method: never the number.
type Card struct {
	Brand string
	Last4 string
}

// Subscription is the provider's view of one org's subscription.
type Subscription struct {
	Ref       string
	Band      Band
	State     string // active, past_due, cancelled, trialing
	PeriodEnd time.Time
	// A downgrade scheduled for the period's end, if any.
	ScheduleRef string
	PendingBand Band
}

// Invoice is one bill, as the billing page lists it.
type Invoice struct {
	ID          string
	Number      string
	Status      string // draft, open, paid, uncollectible, void
	Amount      int64
	Currency    string
	Created     time.Time
	PDF         string
	PayURL      string
	NextAttempt *time.Time
}

// Event is a verified webhook, reduced to what billing acts on.
type Event struct {
	ID       string
	Type     string // one of the Event* constants
	Customer string
	// Set for subscription events: the subscription as it is now.
	Subscription *Subscription
	// Set when a payment method was added.
	Card *Card
	// Set when a payment method was added: the setup to complete.
	SetupRef string
	// Set for a failed payment: the provider's reason, for the email.
	Reason string
}

// The event types billing acts on; anything else is acknowledged and ignored.
const (
	EventSubscriptionUpdated = "subscription.updated"
	EventSubscriptionDeleted = "subscription.deleted"
	EventPaymentSucceeded    = "payment.succeeded"
	EventPaymentFailed       = "payment.failed"
	EventPaymentMethodAdded  = "payment_method.added"
)

// ErrRefused means the provider said no: a declined card, a subscription in
// a state that cannot change. Not retried.
var ErrRefused = errors.New("provider refused")

// ErrBadSignature means a webhook was not the provider's.
var ErrBadSignature = errors.New("webhook signature does not verify")

// Provider is a payment provider.
type Provider interface {
	// Name is the provider's name as stored on the account.
	Name() string
	CreateCustomer(ctx context.Context, orgID, name string) (string, error)
	// SetupURL is the provider's hosted form where a payment method, billing
	// address and tax ID are added; card details never touch our servers.
	SetupURL(ctx context.Context, customer, returnURL string) (string, error)
	// Subscribe starts a subscription on band, charging the card on file,
	// optionally continuing a trial until trialEnd.
	Subscribe(ctx context.Context, customer string, band Band, trialEnd *time.Time) (Subscription, error)
	// ChangeNow moves a subscription to band at once, with proration.
	ChangeNow(ctx context.Context, sub string, band Band) (Subscription, error)
	// ChangeAtPeriodEnd schedules band for when the current period ends.
	ChangeAtPeriodEnd(ctx context.Context, sub string, band Band) (Subscription, error)
	// CancelScheduled drops a scheduled change; the subscription carries on.
	CancelScheduled(ctx context.Context, schedule string) error
	Cancel(ctx context.Context, sub string) error
	// CompleteSetup makes the payment method a setup added the customer's
	// default, and answers what it is.
	CompleteSetup(ctx context.Context, customer, setupRef string) (Card, error)
	Invoices(ctx context.Context, customer string) ([]Invoice, error)
	// Preview is what changing to band now would charge today.
	Preview(ctx context.Context, sub string, band Band) (int64, string, error)
	Prices(ctx context.Context) (map[Band]Price, error)
	// Verify checks a webhook's signature and reduces it to an Event.
	Verify(payload []byte, signature string) (Event, error)
}
