// Package server implements the billing API: the account
// each org has, the payment provider behind it, and the subscription state
// the plan follows. The plan field itself is the organization service's;
// billing is the one path, besides a platform operator, that moves it.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/provider"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/store"
)

// TrialLength is the one trial an org gets.
const TrialLength = 14 * 24 * time.Hour

// GracePeriod is how long a failed payment is retried before the org drops
// to the lowest band.
const GracePeriod = 14 * 24 * time.Hour

// trialBand is what a trial is on: the lowest paid self-serve band, or the
// lowest band of all when a product sells none.
func trialBand() plan.Band {
	if paid := plan.SelfServe(); len(paid) > 0 {
		return paid[0]
	}
	return plan.Lowest()
}

// CheckPrices is nil when every band in a provider's price map is one the
// plan registry sells self-serve. Read at start, after the product has
// filled the registry: a price for a band the ladder does not have, or for
// the lowest or a contractual one, is a deployment mistake, not a request.
func CheckPrices(prices map[provider.Band]string) error {
	sold := plan.SelfServe()
	for b := range prices {
		if !slices.Contains(sold, plan.Band(b)) {
			names := make([]string, len(sold))
			for i, x := range sold {
				names[i] = string(x)
			}
			return fmt.Errorf("billing prices: %q is not a self-serve plan (%s)", b, strings.Join(names, ", "))
		}
	}
	return nil
}

// Server answers the billing API.
type Server struct {
	cluster  *db.Cluster
	logger   *slog.Logger
	recorder audit.Recorder
	authz    authz.Checker
	orgs     Orgs
	members  Members
	notifier Notifier
	provider provider.Provider
	// Where the billing page is, for the provider's form to come back to.
	billingPage string
	now         func() time.Time

	pricesMu sync.Mutex
	prices   map[provider.Band]provider.Price
	pricedAt time.Time
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API. p may be nil: an environment with no payment provider
// set up answers every paid action with a refusal that says so.
func New(cluster *db.Cluster, logger *slog.Logger, recorder audit.Recorder, checker authz.Checker, orgs Orgs, members Members, notifier Notifier, p provider.Provider, billingPage string) *Server {
	return &Server{cluster: cluster, logger: logger, recorder: recorder, authz: checker, orgs: orgs, members: members,
		notifier: notifier, provider: p, billingPage: billingPage, now: time.Now}
}

// WithClock is s reading the time from now: tests of the trial and grace.
func (s *Server) WithClock(now func() time.Time) *Server {
	s.now = now
	return s
}

// Limits is this API's rate limits: one line per endpoint.
var Limits = map[string]ratelimit.Bound{
	"GET /v1/organizations/{org_id}/billing":              ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/billing/setup":       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/billing/band":         ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/billing/band-preview": ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/billing/pending":   ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/billing/trial":       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/billing/auto-upgrade": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/billing/invoices":     ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	// The organization service's data endpoints and closing.
	"GET /v1/internal/organizations/{org_id}/data":    ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/internal/organizations/{org_id}/data": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/internal/users/{user_id}/data":           ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"POST /v1/internal/organizations/{org_id}/close":  ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
}

// Handler is the API's routes, with bad requests and failures answered in
// the error envelope.
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

// Stable codes.
const (
	codeNoProvider    = "billing.unavailable"
	codeNoCard        = "billing.no_payment_method"
	codeRefused       = "billing.refused"
	codeInvoiced      = "billing.invoiced"
	codeTrialUsed     = "billing.trial_used"
	codeSameBand      = "billing.same_band"
	codeNothingToUndo = "billing.nothing_pending"
)

func forbidden(message string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: message}
}

func conflict(code, message string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: code, Message: message}
}

// canBill is the caller's grant when they hold the billing permission.
func (s *Server) canBill(ctx context.Context, org uuid.UUID) (authz.Grant, error) {
	return authz.Require(ctx, s.authz, org.String(), authz.Billing)
}

// errNoProvider means no payment provider is configured here.
var errNoProvider = errors.New("no payment provider")

// account is the org's account, made on first use, with a lapsed trial
// ended at the moment it is read: nothing waits on a scheduler.
func (s *Server) account(ctx context.Context, org uuid.UUID) (store.Account, error) {
	var a store.Account
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		a, err = store.New(tx).EnsureAccount(ctx, store.EnsureAccountParams{OrgID: org, Band: string(plan.Lowest())})
		return err
	})
	if err != nil {
		return a, err
	}
	// The org's plan is contractual: invoiced by contract, every
	// automatic path skipped.
	band, err := s.orgs.Band(ctx, org)
	if err != nil {
		return a, err
	}
	if plan.Contractual(band) && a.State != "invoiced" {
		return s.update(ctx, org, func(a *store.Account) error {
			a.State, a.Band, a.AutoUpgrade = "invoiced", string(band), false
			return nil
		})
	}
	if a.State == "trialing" && !a.SubscriptionRef.Valid && a.TrialEndsAt.Valid && !s.now().Before(a.TrialEndsAt.Time) {
		return s.endTrial(ctx, org)
	}
	return a, nil
}

// update changes the account under a row lock and saves it.
func (s *Server) update(ctx context.Context, org uuid.UUID, change func(a *store.Account) error) (store.Account, error) {
	var out store.Account
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.EnsureAccount(ctx, store.EnsureAccountParams{OrgID: org, Band: string(plan.Lowest())}); err != nil {
			return err
		}
		a, err := q.GetAccountForUpdate(ctx, org)
		if err != nil {
			return err
		}
		if err := change(&a); err != nil {
			return err
		}
		out, err = q.SaveAccount(ctx, store.SaveAccountParams{
			OrgID: org, CustomerRef: a.CustomerRef, SubscriptionRef: a.SubscriptionRef, ScheduleRef: a.ScheduleRef,
			Band: a.Band, State: a.State, PeriodEnd: a.PeriodEnd, PendingBand: a.PendingBand,
			CardBrand: a.CardBrand, CardLast4: a.CardLast4, AutoUpgrade: a.AutoUpgrade, TrialUsed: a.TrialUsed,
			TrialEndsAt: a.TrialEndsAt, GraceStartedAt: a.GraceStartedAt, Notices: a.Notices,
		})
		return err
	})
	return out, err
}

func text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func stamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()} }

// setPlan moves the org's plan and audits the reason on billing's side too.
func (s *Server) setPlan(ctx context.Context, org uuid.UUID, band plan.Band, reason string) error {
	if err := s.orgs.SetPlan(ctx, org, band, reason); err != nil {
		return err
	}
	return s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "billing.plan.changed", TargetType: "organization", TargetID: org.String(),
		Details: map[string]any{"to": string(band), "reason": reason}})
}

// notify tells the org's billing people. Best effort: the change stands
// whether or not the email goes.
func (s *Server) notify(ctx context.Context, org uuid.UUID, id, kind string, data map[string]any) {
	if s.notifier == nil {
		return
	}
	err := s.notifier.Notify(ctx, Notice{ID: "billing:" + id, OrgID: org.String(), Kind: kind, Category: notifycat.Billing, Audience: "billing", Link: "/billing", Data: data})
	if err != nil {
		s.logger.Warn("billing notice not sent", "org_id", org, "kind", kind, "error", err)
	}
}

// money is minor units as the email says it, such as 49.00 USD.
func money(amount int64, currency string) string {
	return fmt.Sprintf("%d.%02d %s", amount/100, amount%100, currency)
}

// endTrial drops a trial that ran out without a card to the lowest band,
// and says what stopped.
func (s *Server) endTrial(ctx context.Context, org uuid.UUID) (store.Account, error) {
	a, err := s.update(ctx, org, func(a *store.Account) error {
		if a.State != "trialing" || a.SubscriptionRef.Valid {
			return nil
		}
		a.State, a.Band, a.TrialEndsAt = "free", string(plan.Lowest()), pgtype.Timestamptz{}
		return nil
	})
	if err != nil || a.State != "free" {
		return a, err
	}
	if err := s.setPlan(ctx, org, plan.Lowest(), "trial_end"); err != nil {
		return a, err
	}
	s.notify(ctx, org, "trial-ended:"+org.String(), "trial_ended", s.checklist(trialBand(), plan.Lowest(),
		"Your trial has ended", fmt.Sprintf("The organization is on the %s plan now. Nothing was deleted and nobody was removed.", plan.Lowest())))
	return a, nil
}

// checklist is an email's data naming what stops on a downgrade.
func (s *Server) checklist(from, to plan.Band, heading, line string) map[string]any {
	stops := []string{}
	for _, c := range plan.Downgrade(from, to) {
		stops = append(stops, c.Message)
	}
	if len(stops) > 0 {
		line += " What stops: " + joinSentences(stops)
	}
	return map[string]any{"heading": heading, "line": line}
}

func joinSentences(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

// pricesNow is the provider's prices, read at most hourly.
func (s *Server) pricesNow(ctx context.Context) map[provider.Band]provider.Price {
	if s.provider == nil {
		return map[provider.Band]provider.Price{}
	}
	s.pricesMu.Lock()
	defer s.pricesMu.Unlock()
	if s.prices != nil && s.now().Sub(s.pricedAt) < time.Hour {
		return s.prices
	}
	prices, err := s.provider.Prices(ctx)
	if err != nil {
		s.logger.Warn("prices not read", "error", err)
		if s.prices != nil {
			return s.prices
		}
		return map[provider.Band]provider.Price{}
	}
	s.prices, s.pricedAt = prices, s.now()
	return prices
}

// view is the account as the billing page and banners read it.
func (s *Server) view(ctx context.Context, org uuid.UUID, a store.Account, grant authz.Grant) (api.Billing, error) {
	active, err := s.members.Active(ctx, org)
	if err != nil {
		return api.Billing{}, err
	}
	band := plan.Band(a.Band)
	out := api.Billing{
		Band: api.Band(a.Band), State: api.BillingState(a.State), AutoUpgrade: a.AutoUpgrade,
		CanManageAutoUpgrade: grant.Role == authz.Owner, Invoiced: a.State == "invoiced",
		TrialAvailable: !a.TrialUsed && a.State == "free", ActiveMembers: active, UsersCap: plan.For(band).Cap(plan.Users),
		Prices: map[string]api.Price{},
	}
	for b, p := range s.pricesNow(ctx) {
		out.Prices[string(b)] = api.Price{Amount: p.Amount, Currency: p.Currency, Interval: p.Interval}
	}
	if next := plan.Next(band); next != band && next != "" && !plan.Contractual(next) {
		n := api.Band(next)
		out.NextBand = &n
	}
	if a.PeriodEnd.Valid {
		out.PeriodEnd = &a.PeriodEnd.Time
	}
	if a.PendingBand.Valid {
		p := api.Band(a.PendingBand.String)
		out.PendingBand = &p
	}
	if a.TrialEndsAt.Valid {
		out.TrialEndsAt = &a.TrialEndsAt.Time
	}
	if a.CardLast4.Valid {
		out.Card = &struct {
			Brand string `json:"brand"`
			Last4 string `json:"last4"`
		}{Brand: a.CardBrand.String, Last4: a.CardLast4.String}
	}
	if a.State == "past_due" && a.GraceStartedAt.Valid {
		left := int(a.GraceStartedAt.Time.Add(GracePeriod).Sub(s.now()).Hours()/24) + 1
		left = max(left, 0)
		out.GraceDaysLeft = &left
	}
	return out, nil
}

// GetBilling is the account, for anyone with the billing permission.
func (s *Server) GetBilling(ctx context.Context, req api.GetBillingRequestObject) (api.GetBillingResponseObject, error) {
	grant, err := s.canBill(ctx, req.OrgId)
	if err != nil {
		return api.GetBilling403JSONResponse{ErrorJSONResponse: forbidden("You do not have permission to see billing.")}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, req.OrgId, a, grant)
	if err != nil {
		return nil, err
	}
	return api.GetBilling200JSONResponse(v), nil
}

// customer is the provider's customer for the org, made the first time.
func (s *Server) customer(ctx context.Context, org uuid.UUID) (string, error) {
	a, err := s.account(ctx, org)
	if err != nil {
		return "", err
	}
	if a.CustomerRef.Valid {
		return a.CustomerRef.String, nil
	}
	name, err := s.orgs.Name(ctx, org)
	if err != nil {
		return "", err
	}
	ref, err := s.provider.CreateCustomer(ctx, org.String(), name)
	if err != nil {
		return "", err
	}
	_, err = s.update(ctx, org, func(a *store.Account) error {
		if !a.CustomerRef.Valid {
			a.CustomerRef = text(ref)
		}
		return nil
	})
	return ref, err
}

// StartSetup is the provider's hosted form for a payment method, billing
// address and tax ID.
func (s *Server) StartSetup(ctx context.Context, req api.StartSetupRequestObject) (api.StartSetupResponseObject, error) {
	if _, err := s.canBill(ctx, req.OrgId); err != nil {
		return api.StartSetup403JSONResponse{ErrorJSONResponse: forbidden("You do not have permission to change billing.")}, nil
	}
	if s.provider == nil {
		return api.StartSetupdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: api.Error{Code: codeNoProvider, Message: "Payments are not set up here."}}, nil
	}
	cus, err := s.customer(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	u, err := s.provider.SetupURL(ctx, cus, s.billingPage)
	if err != nil {
		return nil, err
	}
	return api.StartSetup200JSONResponse{Url: u}, nil
}

// changeUp moves to a higher band now: a subscription starts if there is
// none, and an existing one changes with proration. Then the plan follows.
func (s *Server) changeUp(ctx context.Context, org uuid.UUID, a store.Account, to plan.Band, reason string) (store.Account, error) {
	var sub provider.Subscription
	var err error
	switch {
	case a.SubscriptionRef.Valid:
		sub, err = s.provider.ChangeNow(ctx, a.SubscriptionRef.String, provider.Band(to))
	case a.CardLast4.Valid && a.CustomerRef.Valid:
		var trialEnd *time.Time
		if a.State == "trialing" && a.TrialEndsAt.Valid {
			trialEnd = &a.TrialEndsAt.Time
		}
		sub, err = s.provider.Subscribe(ctx, a.CustomerRef.String, provider.Band(to), trialEnd)
	default:
		return a, errNoCard
	}
	if err != nil {
		return a, err
	}
	a, err = s.update(ctx, org, func(x *store.Account) error {
		x.SubscriptionRef, x.Band, x.PeriodEnd = text(sub.Ref), string(to), stamp(sub.PeriodEnd)
		if sub.State == "trialing" {
			x.State = "trialing"
		} else {
			x.State = "active"
		}
		return nil
	})
	if err != nil {
		return a, err
	}
	return a, s.setPlan(ctx, org, to, reason)
}

var errNoCard = errors.New("no payment method on file")

// ChangeBand moves the org to another band: up now, down at the period end.
func (s *Server) ChangeBand(ctx context.Context, req api.ChangeBandRequestObject) (api.ChangeBandResponseObject, error) {
	grant, err := s.canBill(ctx, req.OrgId)
	if err != nil {
		return api.ChangeBand403JSONResponse(forbidden("You do not have permission to change the plan.")), nil
	}
	if s.provider == nil {
		return api.ChangeBanddefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: api.Error{Code: codeNoProvider, Message: "Payments are not set up here."}}, nil
	}
	to, err := plan.Parse(string(req.Body.Band))
	if err != nil || plan.Contractual(to) {
		return api.ChangeBand400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Choose a self-serve plan."}}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if a.State == "invoiced" {
		return api.ChangeBand409JSONResponse(conflict(codeInvoiced, "Your plan is invoiced by contract; ask your account manager to change it.")), nil
	}
	from := plan.Band(a.Band)
	switch {
	case to == from && !a.PendingBand.Valid:
		return api.ChangeBand409JSONResponse(conflict(codeSameBand, "You are on that plan already.")), nil
	case plan.Rank(to) > plan.Rank(from):
		a, err = s.changeUp(ctx, req.OrgId, a, to, "upgrade")
	default:
		a, err = s.changeDown(ctx, req.OrgId, a, to)
	}
	switch {
	case errors.Is(err, errNoCard):
		return api.ChangeBand409JSONResponse(conflict(codeNoCard, "Add a payment method first.")), nil
	case errors.Is(err, provider.ErrRefused):
		return api.ChangeBand409JSONResponse(conflict(codeRefused, "The payment provider refused the change: "+err.Error())), nil
	case err != nil:
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "billing.band.requested", TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"from": string(from), "to": string(to)}}); err != nil {
		return nil, err
	}
	v, err := s.view(ctx, req.OrgId, a, grant)
	if err != nil {
		return nil, err
	}
	return api.ChangeBand200JSONResponse(v), nil
}

// changeDown schedules a lower band for the period's end: they paid for
// the period. A trial with no card simply ends.
func (s *Server) changeDown(ctx context.Context, org uuid.UUID, a store.Account, to plan.Band) (store.Account, error) {
	if !a.SubscriptionRef.Valid {
		if a.State == "trialing" && to == plan.Lowest() {
			return s.endTrial(ctx, org)
		}
		return a, errNoCard
	}
	if a.ScheduleRef.Valid {
		if err := s.provider.CancelScheduled(ctx, a.ScheduleRef.String); err != nil {
			return a, err
		}
	}
	sub, err := s.provider.ChangeAtPeriodEnd(ctx, a.SubscriptionRef.String, provider.Band(to))
	if err != nil {
		return a, err
	}
	return s.update(ctx, org, func(x *store.Account) error {
		x.ScheduleRef, x.PendingBand, x.PeriodEnd = text(sub.ScheduleRef), text(string(to)), stamp(sub.PeriodEnd)
		return nil
	})
}

// PreviewBand is what a change would charge today.
func (s *Server) PreviewBand(ctx context.Context, req api.PreviewBandRequestObject) (api.PreviewBandResponseObject, error) {
	if _, err := s.canBill(ctx, req.OrgId); err != nil {
		return api.PreviewBand403JSONResponse(forbidden("You do not have permission to see billing.")), nil
	}
	to, err := plan.Parse(string(req.Params.Band))
	if err != nil || s.provider == nil {
		return api.PreviewBand400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Choose a band."}}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := api.PreviewBand200JSONResponse{Band: req.Params.Band, Applies: api.Now}
	if plan.Rank(to) <= plan.Rank(plan.Band(a.Band)) {
		out.Applies = api.PeriodEnd
		return out, nil
	}
	if a.SubscriptionRef.Valid {
		amount, currency, err := s.provider.Preview(ctx, a.SubscriptionRef.String, provider.Band(to))
		if err != nil {
			return nil, err
		}
		out.AmountToday, out.Currency = amount, currency
		return out, nil
	}
	if p, ok := s.pricesNow(ctx)[provider.Band(to)]; ok {
		out.AmountToday, out.Currency = p.Amount, p.Currency
		if a.State == "trialing" {
			out.AmountToday = 0
		}
	}
	return out, nil
}

// CancelPending drops a scheduled downgrade.
func (s *Server) CancelPending(ctx context.Context, req api.CancelPendingRequestObject) (api.CancelPendingResponseObject, error) {
	grant, err := s.canBill(ctx, req.OrgId)
	if err != nil {
		return api.CancelPending403JSONResponse{ErrorJSONResponse: forbidden("You do not have permission to change the plan.")}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if a.ScheduleRef.Valid && s.provider != nil {
		if err := s.provider.CancelScheduled(ctx, a.ScheduleRef.String); err != nil {
			return nil, err
		}
	}
	a, err = s.update(ctx, req.OrgId, func(x *store.Account) error {
		x.ScheduleRef, x.PendingBand = pgtype.Text{}, pgtype.Text{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "billing.downgrade.cancelled", TargetType: "organization", TargetID: req.OrgId.String()}); err != nil {
		return nil, err
	}
	v, err := s.view(ctx, req.OrgId, a, grant)
	if err != nil {
		return nil, err
	}
	return api.CancelPending200JSONResponse(v), nil
}

// StartTrial starts the org's one trial.
func (s *Server) StartTrial(ctx context.Context, req api.StartTrialRequestObject) (api.StartTrialResponseObject, error) {
	grant, err := s.canBill(ctx, req.OrgId)
	if err != nil {
		return api.StartTrial403JSONResponse{ErrorJSONResponse: forbidden("You do not have permission to change the plan.")}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if a.TrialUsed || a.State != "free" {
		return api.StartTrial409JSONResponse(conflict(codeTrialUsed, "The trial is for an organization on the lowest plan that has not had one.")), nil
	}
	ends := s.now().Add(TrialLength)
	a, err = s.update(ctx, req.OrgId, func(x *store.Account) error {
		x.State, x.Band, x.TrialUsed, x.TrialEndsAt = "trialing", string(trialBand()), true, stamp(ends)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.setPlan(ctx, req.OrgId, trialBand(), "trial_start"); err != nil {
		return nil, err
	}
	v, err := s.view(ctx, req.OrgId, a, grant)
	if err != nil {
		return nil, err
	}
	return api.StartTrial200JSONResponse(v), nil
}

// SetAutoUpgrade is an Owner's call, audited.
func (s *Server) SetAutoUpgrade(ctx context.Context, req api.SetAutoUpgradeRequestObject) (api.SetAutoUpgradeResponseObject, error) {
	grant, err := s.canBill(ctx, req.OrgId)
	if err != nil || grant.Role != authz.Owner {
		return api.SetAutoUpgrade403JSONResponse{ErrorJSONResponse: forbidden("Only an Owner turns automatic upgrade on or off.")}, nil
	}
	a, err := s.update(ctx, req.OrgId, func(x *store.Account) error {
		x.AutoUpgrade = req.Body.On && x.State != "invoiced"
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "billing.auto_upgrade.changed", TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"on": a.AutoUpgrade}}); err != nil {
		return nil, err
	}
	v, err := s.view(ctx, req.OrgId, a, grant)
	if err != nil {
		return nil, err
	}
	return api.SetAutoUpgrade200JSONResponse(v), nil
}

// ListInvoices is the provider's invoices.
func (s *Server) ListInvoices(ctx context.Context, req api.ListInvoicesRequestObject) (api.ListInvoicesResponseObject, error) {
	if _, err := s.canBill(ctx, req.OrgId); err != nil {
		return api.ListInvoices403JSONResponse{ErrorJSONResponse: forbidden("You do not have permission to see billing.")}, nil
	}
	out := api.ListInvoices200JSONResponse{Invoices: []api.Invoice{}}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if s.provider == nil || !a.CustomerRef.Valid {
		return out, nil
	}
	invoices, err := s.provider.Invoices(ctx, a.CustomerRef.String)
	if err != nil {
		return nil, err
	}
	for _, i := range invoices {
		inv := api.Invoice{Id: i.ID, Status: i.Status, Amount: i.Amount, Currency: i.Currency, Created: i.Created, NextAttempt: i.NextAttempt}
		if i.Number != "" {
			inv.Number = &i.Number
		}
		if i.PDF != "" {
			inv.Pdf = &i.PDF
		}
		if i.PayURL != "" {
			inv.PayUrl = &i.PayURL
		}
		out.Invoices = append(out.Invoices, inv)
	}
	return out, nil
}

// bandFor is the smallest self-serve band with room for members, or none.
func bandFor(members int) (plan.Band, bool) {
	for _, b := range plan.SelfServe() {
		if c := plan.For(b).Cap(plan.Users); c == plan.Unlimited || c >= members {
			return b, true
		}
	}
	return "", false
}

// MakeRoom is the one path that moves a plan without a person clicking:
// up, once per crossing, only for a team org with a card on file and
// automatic upgrade on. The plan moves only once the provider agreed.
func (s *Server) MakeRoom(ctx context.Context, req api.MakeRoomRequestObject) (api.MakeRoomResponseObject, error) {
	if err := auth.RequireService(ctx, "user"); err != nil {
		return api.MakeRoom403JSONResponse{ErrorJSONResponse: forbidden("The user service only.")}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	from := plan.Band(a.Band)
	members := req.Body.Members
	if cap := plan.For(from).Cap(plan.Users); cap == plan.Unlimited || members <= cap {
		return api.MakeRoom200JSONResponse{Band: api.Band(from), Upgraded: false}, nil
	}
	refuse := func() (api.MakeRoomResponseObject, error) {
		r, _ := plan.AsRefusal(plan.CheckUsers(from, plan.For(from).Cap(plan.Users)))
		msg := "The plan has no room for more members."
		if r != nil {
			msg = r.Message
		}
		return api.MakeRoom409JSONResponse(conflict(plan.Code, msg)), nil
	}
	eligible := s.provider != nil && a.AutoUpgrade && a.CardLast4.Valid && a.SubscriptionRef.Valid &&
		(a.State == "active" || a.State == "trialing") && plan.Rank(from) > plan.Rank(plan.Lowest())
	to, ok := bandFor(members)
	if !eligible || !ok || plan.Rank(to) <= plan.Rank(from) {
		return refuse()
	}
	var amount int64
	var currency string
	if amt, cur, err := s.provider.Preview(ctx, a.SubscriptionRef.String, provider.Band(to)); err == nil {
		amount, currency = amt, cur
	}
	if _, err := s.changeUp(ctx, req.OrgId, a, to, "upgrade"); err != nil {
		if errors.Is(err, provider.ErrRefused) {
			s.logger.Warn("automatic upgrade refused by the provider", "org_id", req.OrgId)
			return refuse()
		}
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "billing.auto_upgraded", TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"from": string(from), "to": string(to), "members": members}}); err != nil {
		return nil, err
	}
	line := fmt.Sprintf("You passed the %s plan's %d members, so the organization moved to %s.", from, plan.For(from).Cap(plan.Users), to)
	if currency != "" {
		line += " Charged today, prorated: " + money(amount, currency) + "."
	}
	s.notify(ctx, req.OrgId, fmt.Sprintf("upgraded:%s:%s", req.OrgId, to), "auto_upgraded", map[string]any{
		"heading": fmt.Sprintf("Your plan moved up to %s", to), "line": line + " The invoice follows from the payment provider.",
	})
	return api.MakeRoom200JSONResponse{Band: api.Band(to), Upgraded: true}, nil
}

// MembersChanged warns once per band when the org reaches 80% of its cap.
func (s *Server) MembersChanged(ctx context.Context, req api.MembersChangedRequestObject) (api.MembersChangedResponseObject, error) {
	if err := auth.RequireService(ctx, "user"); err != nil {
		return api.MembersChanged403JSONResponse{ErrorJSONResponse: forbidden("The user service only.")}, nil
	}
	a, err := s.account(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	band := plan.Band(a.Band)
	cap := plan.For(band).Cap(plan.Users)
	notice := "warn80:" + string(band)
	if cap == plan.Unlimited || a.State == "invoiced" || req.Body.Members*5 < cap*4 || slices.Contains(a.Notices, notice) {
		return api.MembersChanged204Response{}, nil
	}
	if _, err := s.update(ctx, req.OrgId, func(x *store.Account) error {
		x.Notices = append(x.Notices, notice)
		return nil
	}); err != nil {
		return nil, err
	}
	next := plan.Next(band)
	line := fmt.Sprintf("You have %d of the %d members the %s plan allows.", req.Body.Members, cap, band)
	if p, ok := s.pricesNow(ctx)[provider.Band(next)]; ok && !plan.Contractual(next) {
		line += fmt.Sprintf(" The next plan, %s, is %s a %s.", next, money(p.Amount, p.Currency), p.Interval)
	}
	if a.AutoUpgrade {
		line += " Automatic upgrade is on: passing the cap moves you up, and an Owner can turn it off on the billing page."
	} else {
		line += " Automatic upgrade is off: invitations past the cap will be refused until the plan changes."
	}
	s.notify(ctx, req.OrgId, fmt.Sprintf("%s:%s", notice, req.OrgId), "cap_warning", map[string]any{
		"heading": fmt.Sprintf("You are close to your plan's %d members", cap), "line": line,
	})
	return api.MembersChanged204Response{}, nil
}
