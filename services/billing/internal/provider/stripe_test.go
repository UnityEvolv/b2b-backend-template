package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sign(secret string, at time.Time, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", at.Unix())
	mac.Write(payload)
	return fmt.Sprintf("t=%d,v1=%s", at.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func TestStripeVerify(t *testing.T) {
	s := NewStripe("https://stripe.test", "sk", "whsec_test", map[Band]string{"team": "price_team"}, nil)
	now := time.Now()
	sub := []byte(`{"id":"evt_1","type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"past_due","current_period_end":1790000000,"customer":"cus_1","cancel_at_period_end":true,"items":{"data":[{"id":"si_1","price":{"id":"price_team"}}]}}}}`)
	ev, err := s.Verify(sub, sign("whsec_test", now, sub))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != EventSubscriptionUpdated || ev.Customer != "cus_1" || ev.Subscription.Band != "team" || ev.Subscription.State != "past_due" || ev.Subscription.PendingBand != "free" {
		t.Errorf("event: %+v %+v", ev, ev.Subscription)
	}
	if _, err := s.Verify(sub, sign("other", now, sub)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a wrong secret: %v", err)
	}
	if _, err := s.Verify(sub, sign("whsec_test", now.Add(-10*time.Minute), sub)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("an old signature: %v", err)
	}
	failed := []byte(`{"id":"evt_2","type":"invoice.payment_failed","data":{"object":{"customer":"cus_1"}}}`)
	if ev, _ := s.Verify(failed, sign("whsec_test", now, failed)); ev.Type != EventPaymentFailed || ev.Reason == "" {
		t.Errorf("failed: %+v", ev)
	}
	setup := []byte(`{"id":"evt_3","type":"checkout.session.completed","data":{"object":{"mode":"setup","customer":"cus_1","setup_intent":"seti_1"}}}`)
	if ev, _ := s.Verify(setup, sign("whsec_test", now, setup)); ev.Type != EventPaymentMethodAdded || ev.SetupRef != "seti_1" {
		t.Errorf("setup: %+v", ev)
	}
}

func TestParsePrices(t *testing.T) {
	p, err := ParsePrices(" team=price_a, business=price_b ")
	if err != nil || p["team"] != "price_a" || p["business"] != "price_b" {
		t.Errorf("%v %v", p, err)
	}
	if _, err := ParsePrices("team"); err == nil {
		t.Error("no price")
	}
}

// The lowest band is the registry's, whatever the product names it: a
// move to it cancels at the period's end, and the webhook reports it as
// the pending band.
func TestLowestBandIsTheRegistrys(t *testing.T) {
	var got []string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = append(got, r.Method+" "+r.URL.Path+" "+r.PostForm.Encode())
		fmt.Fprint(w, `{"id":"sub_1","status":"active","current_period_end":1790000000,"cancel_at_period_end":true,"items":{"data":[{"id":"si_1","price":{"id":"price_pro"}}]}}`)
	}))
	defer stripe.Close()
	s := NewStripe(stripe.URL, "sk", "whsec_test", map[Band]string{"pro": "price_pro"}, nil).WithLowest("starter")

	sub, err := s.ChangeAtPeriodEnd(context.Background(), "sub_1", "starter")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "POST /v1/subscriptions/sub_1 cancel_at_period_end=true" {
		t.Errorf("requests: %v", got)
	}
	if sub.PendingBand != "starter" || sub.ScheduleRef != "cancel:sub_1" || sub.Band != "pro" {
		t.Errorf("subscription: %+v", sub)
	}
	// "free" is only a band like any other when the product has one; here
	// it has no price, so there is nothing to schedule.
	if _, err := s.ChangeAtPeriodEnd(context.Background(), "sub_1", "free"); err == nil {
		t.Error("an unknown band scheduled")
	}
	if NewStripe(stripe.URL, "sk", "", nil, nil).WithLowest("").lowest != "free" {
		t.Error("the default lowest band")
	}
}
