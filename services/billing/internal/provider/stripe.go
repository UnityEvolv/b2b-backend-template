package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// StripeVersion pins the API's shapes, so a Stripe release never changes
// what this client reads.
const StripeVersion = "2024-06-20"

// Stripe is the Stripe provider, over its REST API directly.
type Stripe struct {
	base          string
	key           string
	webhookSecret string
	// The price each band is sold at, and back.
	prices map[Band]string
	bands  map[string]Band
	http   *http.Client
	now    func() time.Time
}

// NewStripe is Stripe at base (its API origin, from config) with a secret
// key, the webhook signing secret, and "band=price_id" pairs.
func NewStripe(base, key, webhookSecret string, prices map[Band]string, client *http.Client) *Stripe {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	bands := map[string]Band{}
	for b, p := range prices {
		bands[p] = b
	}
	return &Stripe{base: strings.TrimRight(base, "/"), key: key, webhookSecret: webhookSecret, prices: prices, bands: bands, http: client, now: time.Now}
}

// ParsePrices reads "team-50=price_a,team-200=price_b".
func ParsePrices(s string) (map[Band]string, error) {
	out := map[Band]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		b, p, ok := strings.Cut(pair, "=")
		if !ok || b == "" || p == "" {
			return nil, fmt.Errorf("stripe prices: %q is not band=price", pair)
		}
		out[Band(strings.TrimSpace(b))] = strings.TrimSpace(p)
	}
	return out, nil
}

func (s *Stripe) Name() string { return "stripe" }

type stripeError struct {
	Error struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call is one API request; a 402 or a card error is ErrRefused.
func (s *Stripe) call(ctx context.Context, method, path string, form url.Values, out any) error {
	var body io.Reader
	u := s.base + path
	if method == http.MethodGet && len(form) > 0 {
		u += "?" + form.Encode()
	} else if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.key, "")
	req.Header.Set("Stripe-Version", StripeVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("stripe: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e stripeError
		_ = json.Unmarshal(raw, &e)
		if resp.StatusCode == http.StatusPaymentRequired || e.Error.Type == "card_error" {
			return fmt.Errorf("%w: %s", ErrRefused, e.Error.Message)
		}
		return fmt.Errorf("stripe answered %d: %s", resp.StatusCode, e.Error.Code)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (s *Stripe) CreateCustomer(ctx context.Context, orgID, name string) (string, error) {
	var c struct {
		ID string `json:"id"`
	}
	err := s.call(ctx, http.MethodPost, "/v1/customers", url.Values{"name": {name}, "metadata[org_id]": {orgID}}, &c)
	return c.ID, err
}

func (s *Stripe) SetupURL(ctx context.Context, customer, returnURL string) (string, error) {
	var session struct {
		URL string `json:"url"`
	}
	sep := "?"
	if strings.Contains(returnURL, "?") {
		sep = "&"
	}
	err := s.call(ctx, http.MethodPost, "/v1/checkout/sessions", url.Values{
		"mode":                       {"setup"},
		"customer":                   {customer},
		"payment_method_types[]":     {"card"},
		"billing_address_collection": {"required"},
		"tax_id_collection[enabled]": {"true"},
		"customer_update[address]":   {"auto"},
		"customer_update[name]":      {"auto"},
		"success_url":                {returnURL + sep + "setup=done"},
		"cancel_url":                 {returnURL + sep + "setup=cancelled"},
	}, &session)
	return session.URL, err
}

// stripeSubscription is the part of a Stripe subscription billing reads.
type stripeSubscription struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	CurrentPeriodEnd int64  `json:"current_period_end"`
	Customer         string `json:"customer"`
	Schedule         any    `json:"schedule"`
	CancelAtEnd      bool   `json:"cancel_at_period_end"`
	Items            struct {
		Data []struct {
			ID    string `json:"id"`
			Price struct {
				ID string `json:"id"`
			} `json:"price"`
		} `json:"data"`
	} `json:"items"`
}

func (s *Stripe) toSubscription(sub stripeSubscription) Subscription {
	out := Subscription{Ref: sub.ID, PeriodEnd: time.Unix(sub.CurrentPeriodEnd, 0).UTC()}
	if len(sub.Items.Data) > 0 {
		out.Band = s.bands[sub.Items.Data[0].Price.ID]
	}
	switch sub.Status {
	case "active":
		out.State = "active"
	case "trialing":
		out.State = "trialing"
	case "past_due", "unpaid", "incomplete":
		out.State = "past_due"
	default:
		out.State = "cancelled"
	}
	if sub.CancelAtEnd {
		// A move to free is a cancellation at the period's end.
		out.ScheduleRef, out.PendingBand = cancelPrefix+sub.ID, "free"
	}
	switch v := sub.Schedule.(type) {
	case string:
		out.ScheduleRef = v
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			out.ScheduleRef = id
		}
	}
	return out
}

func (s *Stripe) price(band Band) (string, error) {
	p, ok := s.prices[band]
	if !ok {
		return "", fmt.Errorf("stripe: no price for %s", band)
	}
	return p, nil
}

func (s *Stripe) Subscribe(ctx context.Context, customer string, band Band, trialEnd *time.Time) (Subscription, error) {
	price, err := s.price(band)
	if err != nil {
		return Subscription{}, err
	}
	form := url.Values{
		"customer":               {customer},
		"items[0][price]":        {price},
		"automatic_tax[enabled]": {"true"},
		"payment_behavior":       {"error_if_incomplete"},
		"metadata[source]":       {"unityofis"},
	}
	if trialEnd != nil && trialEnd.After(s.now()) {
		form.Set("trial_end", strconv.FormatInt(trialEnd.Unix(), 10))
	}
	var sub stripeSubscription
	if err := s.call(ctx, http.MethodPost, "/v1/subscriptions", form, &sub); err != nil {
		return Subscription{}, err
	}
	return s.toSubscription(sub), nil
}

func (s *Stripe) get(ctx context.Context, sub string) (stripeSubscription, error) {
	var out stripeSubscription
	err := s.call(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(sub), nil, &out)
	return out, err
}

func (s *Stripe) ChangeNow(ctx context.Context, sub string, band Band) (Subscription, error) {
	price, err := s.price(band)
	if err != nil {
		return Subscription{}, err
	}
	current, err := s.get(ctx, sub)
	if err != nil {
		return Subscription{}, err
	}
	if len(current.Items.Data) == 0 {
		return Subscription{}, fmt.Errorf("%w: the subscription has no item", ErrRefused)
	}
	var out stripeSubscription
	err = s.call(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub), url.Values{
		"items[0][id]":       {current.Items.Data[0].ID},
		"items[0][price]":    {price},
		"proration_behavior": {"always_invoice"},
		"payment_behavior":   {"error_if_incomplete"},
	}, &out)
	if err != nil {
		return Subscription{}, err
	}
	return s.toSubscription(out), nil
}

// cancelPrefix marks a scheduled move to free, which Stripe keeps as a
// cancellation at the period's end rather than a schedule.
const cancelPrefix = "cancel:"

func (s *Stripe) ChangeAtPeriodEnd(ctx context.Context, sub string, band Band) (Subscription, error) {
	if band == "free" {
		var out stripeSubscription
		if err := s.call(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub), url.Values{"cancel_at_period_end": {"true"}}, &out); err != nil {
			return Subscription{}, err
		}
		return s.toSubscription(out), nil
	}
	price, err := s.price(band)
	if err != nil {
		return Subscription{}, err
	}
	var schedule struct {
		ID     string `json:"id"`
		Phases []struct {
			StartDate int64 `json:"start_date"`
			EndDate   int64 `json:"end_date"`
			Items     []struct {
				Price any `json:"price"`
			} `json:"items"`
		} `json:"phases"`
	}
	if err := s.call(ctx, http.MethodPost, "/v1/subscription_schedules", url.Values{"from_subscription": {sub}}, &schedule); err != nil {
		return Subscription{}, err
	}
	if len(schedule.Phases) == 0 || len(schedule.Phases[0].Items) == 0 {
		return Subscription{}, errors.New("stripe: a schedule with no phase")
	}
	now := schedule.Phases[0]
	currentPrice, _ := now.Items[0].Price.(string)
	if m, ok := now.Items[0].Price.(map[string]any); ok {
		currentPrice, _ = m["id"].(string)
	}
	err = s.call(ctx, http.MethodPost, "/v1/subscription_schedules/"+url.PathEscape(schedule.ID), url.Values{
		"end_behavior":                  {"release"},
		"phases[0][items][0][price]":    {currentPrice},
		"phases[0][start_date]":         {strconv.FormatInt(now.StartDate, 10)},
		"phases[0][end_date]":           {strconv.FormatInt(now.EndDate, 10)},
		"phases[1][items][0][price]":    {price},
		"phases[1][iterations]":         {"1"},
		"phases[1][proration_behavior]": {"none"},
	}, nil)
	if err != nil {
		return Subscription{}, err
	}
	current, err := s.get(ctx, sub)
	if err != nil {
		return Subscription{}, err
	}
	out := s.toSubscription(current)
	out.ScheduleRef = schedule.ID
	out.PendingBand = band
	return out, nil
}

func (s *Stripe) CancelScheduled(ctx context.Context, schedule string) error {
	if sub, ok := strings.CutPrefix(schedule, cancelPrefix); ok {
		return s.call(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub), url.Values{"cancel_at_period_end": {"false"}}, nil)
	}
	return s.call(ctx, http.MethodPost, "/v1/subscription_schedules/"+url.PathEscape(schedule)+"/release", url.Values{}, nil)
}

func (s *Stripe) Cancel(ctx context.Context, sub string) error {
	return s.call(ctx, http.MethodDelete, "/v1/subscriptions/"+url.PathEscape(sub), nil, nil)
}

func (s *Stripe) CompleteSetup(ctx context.Context, customer, setupRef string) (Card, error) {
	var intent struct {
		PaymentMethod string `json:"payment_method"`
	}
	if err := s.call(ctx, http.MethodGet, "/v1/setup_intents/"+url.PathEscape(setupRef), nil, &intent); err != nil {
		return Card{}, err
	}
	if intent.PaymentMethod == "" {
		return Card{}, errors.New("stripe: the setup has no payment method")
	}
	if err := s.call(ctx, http.MethodPost, "/v1/customers/"+url.PathEscape(customer), url.Values{
		"invoice_settings[default_payment_method]": {intent.PaymentMethod},
	}, nil); err != nil {
		return Card{}, err
	}
	var pm struct {
		Card struct {
			Brand string `json:"brand"`
			Last4 string `json:"last4"`
		} `json:"card"`
	}
	if err := s.call(ctx, http.MethodGet, "/v1/payment_methods/"+url.PathEscape(intent.PaymentMethod), nil, &pm); err != nil {
		return Card{}, err
	}
	return Card{Brand: pm.Card.Brand, Last4: pm.Card.Last4}, nil
}

func (s *Stripe) Invoices(ctx context.Context, customer string) ([]Invoice, error) {
	var list struct {
		Data []struct {
			ID               string `json:"id"`
			Number           string `json:"number"`
			Status           string `json:"status"`
			AmountDue        int64  `json:"amount_due"`
			Currency         string `json:"currency"`
			Created          int64  `json:"created"`
			InvoicePDF       string `json:"invoice_pdf"`
			HostedInvoiceURL string `json:"hosted_invoice_url"`
			NextAttempt      *int64 `json:"next_payment_attempt"`
		} `json:"data"`
	}
	if err := s.call(ctx, http.MethodGet, "/v1/invoices", url.Values{"customer": {customer}, "limit": {"24"}}, &list); err != nil {
		return nil, err
	}
	out := make([]Invoice, 0, len(list.Data))
	for _, i := range list.Data {
		inv := Invoice{ID: i.ID, Number: i.Number, Status: i.Status, Amount: i.AmountDue, Currency: i.Currency,
			Created: time.Unix(i.Created, 0).UTC(), PDF: i.InvoicePDF, PayURL: i.HostedInvoiceURL}
		if i.NextAttempt != nil {
			t := time.Unix(*i.NextAttempt, 0).UTC()
			inv.NextAttempt = &t
		}
		out = append(out, inv)
	}
	return out, nil
}

func (s *Stripe) Preview(ctx context.Context, sub string, band Band) (int64, string, error) {
	price, err := s.price(band)
	if err != nil {
		return 0, "", err
	}
	current, err := s.get(ctx, sub)
	if err != nil {
		return 0, "", err
	}
	if len(current.Items.Data) == 0 {
		return 0, "", errors.New("stripe: the subscription has no item")
	}
	var upcoming struct {
		AmountDue int64  `json:"amount_due"`
		Currency  string `json:"currency"`
	}
	err = s.call(ctx, http.MethodGet, "/v1/invoices/upcoming", url.Values{
		"customer":                        {current.Customer},
		"subscription":                    {sub},
		"subscription_items[0][id]":       {current.Items.Data[0].ID},
		"subscription_items[0][price]":    {price},
		"subscription_proration_behavior": {"always_invoice"},
	}, &upcoming)
	return upcoming.AmountDue, upcoming.Currency, err
}

func (s *Stripe) Prices(ctx context.Context) (map[Band]Price, error) {
	out := map[Band]Price{}
	for band, id := range s.prices {
		var p struct {
			UnitAmount int64  `json:"unit_amount"`
			Currency   string `json:"currency"`
			Recurring  struct {
				Interval string `json:"interval"`
			} `json:"recurring"`
		}
		if err := s.call(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(id), nil, &p); err != nil {
			return nil, err
		}
		out[band] = Price{Amount: p.UnitAmount, Currency: p.Currency, Interval: p.Recurring.Interval}
	}
	return out, nil
}

// signatureTolerance is how old a signed webhook may be.
const signatureTolerance = 5 * time.Minute

// Verify checks the Stripe-Signature header (t=...,v1=...) against the
// signing secret and reduces the event to what billing acts on.
func (s *Stripe) Verify(payload []byte, signature string) (Event, error) {
	var ts string
	var sigs []string
	for _, part := range strings.Split(signature, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 || s.webhookSecret == "" {
		return Event{}, ErrBadSignature
	}
	if d := s.now().Sub(time.Unix(unix, 0)); d > signatureTolerance || d < -signatureTolerance {
		return Event{}, ErrBadSignature
	}
	mac := hmac.New(sha256.New, []byte(s.webhookSecret))
	mac.Write([]byte(ts + "."))
	mac.Write(payload)
	want := mac.Sum(nil)
	ok := false
	for _, sig := range sigs {
		got, err := hex.DecodeString(sig)
		if err == nil && hmac.Equal(got, want) {
			ok = true
		}
	}
	if !ok {
		return Event{}, ErrBadSignature
	}
	var raw struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Data struct {
			Object json.RawMessage `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Event{}, err
	}
	ev := Event{ID: raw.ID}
	switch raw.Type {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		var sub stripeSubscription
		if err := json.Unmarshal(raw.Data.Object, &sub); err != nil {
			return Event{}, err
		}
		converted := s.toSubscription(sub)
		ev.Customer, ev.Subscription = sub.Customer, &converted
		ev.Type = EventSubscriptionUpdated
		if raw.Type == "customer.subscription.deleted" {
			ev.Type = EventSubscriptionDeleted
		}
	case "invoice.paid", "invoice.payment_failed":
		var inv struct {
			Customer            string `json:"customer"`
			LastFinalizationErr *struct {
				Message string `json:"message"`
			} `json:"last_finalization_error"`
		}
		if err := json.Unmarshal(raw.Data.Object, &inv); err != nil {
			return Event{}, err
		}
		ev.Customer = inv.Customer
		ev.Type = EventPaymentSucceeded
		if raw.Type == "invoice.payment_failed" {
			ev.Type = EventPaymentFailed
			ev.Reason = "The card was declined."
			if inv.LastFinalizationErr != nil && inv.LastFinalizationErr.Message != "" {
				ev.Reason = inv.LastFinalizationErr.Message
			}
		}
	case "checkout.session.completed":
		var session struct {
			Mode        string `json:"mode"`
			Customer    string `json:"customer"`
			SetupIntent string `json:"setup_intent"`
		}
		if err := json.Unmarshal(raw.Data.Object, &session); err != nil {
			return Event{}, err
		}
		if session.Mode == "setup" {
			ev.Type, ev.Customer, ev.SetupRef = EventPaymentMethodAdded, session.Customer, session.SetupIntent
		}
	}
	return ev, nil
}
