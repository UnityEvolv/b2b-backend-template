package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/provider"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/server"
)

type recorder struct{}

func (recorder) Record(context.Context, audit.Event) error { return nil }

// orgs is the organization and user services.
type orgs struct {
	mu      sync.Mutex
	bands   map[uuid.UUID]plan.Band
	reasons []string
	members int
}

func (o *orgs) Band(_ context.Context, org uuid.UUID) (plan.Band, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b, ok := o.bands[org]; ok {
		return b, nil
	}
	return plan.Free, nil
}

func (o *orgs) SetPlan(_ context.Context, org uuid.UUID, band plan.Band, reason string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.bands[org] = band
	o.reasons = append(o.reasons, reason)
	return nil
}

func (o *orgs) Name(context.Context, uuid.UUID) (string, error) { return "Acme", nil }

func (o *orgs) Active(context.Context, uuid.UUID) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.members, nil
}

type notices struct {
	mu   sync.Mutex
	sent []server.Notice
}

func (n *notices) Notify(_ context.Context, x server.Notice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, x)
	return nil
}

func (n *notices) kinds() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []string{}
	for _, x := range n.sent {
		out = append(out, x.Kind)
	}
	n.sent = nil
	return out
}

// fake is the payment provider.
type fake struct {
	mu       sync.Mutex
	subs     map[string]provider.Subscription
	decline  bool
	calls    []string
	customer int
}

func (f *fake) Name() string { return "fake" }
func (f *fake) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}
func (f *fake) CreateCustomer(context.Context, string, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.customer++
	return fmt.Sprintf("cus_%d_%s", f.customer, uuid.NewString()[:8]), nil
}
func (f *fake) SetupURL(_ context.Context, customer, back string) (string, error) {
	return "https://pay.example/setup?c=" + customer + "&back=" + back, nil
}
func (f *fake) Subscribe(_ context.Context, customer string, band provider.Band, trialEnd *time.Time) (provider.Subscription, error) {
	if f.decline {
		return provider.Subscription{}, provider.ErrRefused
	}
	f.record("subscribe:" + string(band))
	state := "active"
	if trialEnd != nil {
		state = "trialing"
	}
	sub := provider.Subscription{Ref: "sub_" + customer, Band: band, State: state, PeriodEnd: time.Now().Add(30 * 24 * time.Hour)}
	f.mu.Lock()
	f.subs[sub.Ref] = sub
	f.mu.Unlock()
	return sub, nil
}
func (f *fake) ChangeNow(_ context.Context, ref string, band provider.Band) (provider.Subscription, error) {
	if f.decline {
		return provider.Subscription{}, provider.ErrRefused
	}
	f.record("change:" + string(band))
	f.mu.Lock()
	defer f.mu.Unlock()
	sub := f.subs[ref]
	sub.Band = band
	f.subs[ref] = sub
	return sub, nil
}
func (f *fake) ChangeAtPeriodEnd(_ context.Context, ref string, band provider.Band) (provider.Subscription, error) {
	f.record("schedule:" + string(band))
	f.mu.Lock()
	defer f.mu.Unlock()
	sub := f.subs[ref]
	sub.ScheduleRef, sub.PendingBand = "sched_"+ref, band
	return sub, nil
}
func (f *fake) CancelScheduled(context.Context, string) error { f.record("unschedule"); return nil }
func (f *fake) Cancel(_ context.Context, ref string) error    { f.record("cancel:" + ref); return nil }
func (f *fake) CompleteSetup(context.Context, string, string) (provider.Card, error) {
	return provider.Card{Brand: "visa", Last4: "4242"}, nil
}
func (f *fake) Invoices(context.Context, string) ([]provider.Invoice, error) {
	return []provider.Invoice{{ID: "in_1", Status: "paid", Amount: 4900, Currency: "usd", Created: time.Now()}}, nil
}
func (f *fake) Preview(context.Context, string, provider.Band) (int64, string, error) {
	return 2500, "usd", nil
}
func (f *fake) Prices(context.Context) (map[provider.Band]provider.Price, error) {
	return map[provider.Band]provider.Price{"team-50": {Amount: 4900, Currency: "usd", Interval: "month"}, "team-200": {Amount: 14900, Currency: "usd", Interval: "month"}}, nil
}
func (f *fake) Verify([]byte, string) (provider.Event, error) { return provider.Event{}, nil }

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return time.Now()
	}
	return c.at
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = t
}

type fixture struct {
	h       http.Handler
	srv     *server.Server
	issuer  *stubissuer.Issuer
	grants  authz.Static
	orgs    *orgs
	notices *notices
	pay     *fake
	clock   *clock
	org     uuid.UUID
	user    string
}

func newAPI(t *testing.T) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("billing")
	config, _ := pgxpool.ParseConfig(url)
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrator, _ := db.Migrator(stdlib.OpenDBFromPool(pool), service, migrations.FS)
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, _ := stubissuer.New("test", "unityofis")
	verifier := auth.NewStaticVerifier("test", "unityofis", issuer.PublicKeys())
	f := &fixture{issuer: issuer, grants: authz.Static{}, orgs: &orgs{bands: map[uuid.UUID]plan.Band{}}, notices: &notices{},
		pay: &fake{subs: map[string]provider.Subscription{}}, clock: &clock{}, org: uuid.Must(uuid.NewV7())}
	f.srv = server.New(db.SingleShard(pool), slog.New(slog.NewTextHandler(io.Discard, nil)), recorder{}, f.grants, f.orgs, f.orgs, f.notices, f.pay, "https://admin.test/billing").WithClock(f.clock.now)
	root := http.NewServeMux()
	root.Handle("/", auth.Require(verifier, f.srv.Handler(httpx.NewMux())))
	f.h = root
	f.user = f.token(t, auth.Caller{Service: "user"})
	return f
}

func (f *fixture) token(t *testing.T, c auth.Caller) string {
	t.Helper()
	raw, err := f.issuer.Issue(c, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) member(t *testing.T, role authz.Role) string {
	t.Helper()
	mbr := uuid.NewString()
	f.grants[f.org.String()+"/"+mbr] = authz.Grant{Role: role, Permissions: authz.Effective(role, authz.Defaults())}
	return f.token(t, auth.Caller{UserID: uuid.NewString(), OrgID: f.org.String(), MembershipID: mbr})
}

func (f *fixture) do(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (f *fixture) path(rest string) string { return "/v1/organizations/" + f.org.String() + rest }

// card walks the provider's form: the setup, then its webhook.
func (f *fixture) card(t *testing.T, owner string) {
	t.Helper()
	code, out := f.do(t, http.MethodPost, f.path("/billing/setup"), owner, nil)
	if code != http.StatusOK || !strings.Contains(out["url"].(string), "back=https://admin.test/billing") {
		t.Fatalf("setup: %d %v", code, out)
	}
	customer := strings.Split(strings.Split(out["url"].(string), "c=")[1], "&")[0]
	if err := f.srv.HandleEvent(context.Background(), provider.Event{ID: "evt_card_" + customer, Type: provider.EventPaymentMethodAdded, Customer: customer, SetupRef: "seti_1"}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) customer(t *testing.T, owner string) string {
	t.Helper()
	_, out := f.do(t, http.MethodPost, f.path("/billing/setup"), owner, nil)
	return strings.Split(strings.Split(out["url"].(string), "c=")[1], "&")[0]
}

// The payment story's "done when": a card, a subscription to team-50, the
// account matching the provider, and a replayed webhook changing nothing.
func TestSubscribe(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	if code, out := f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-50"}); code != http.StatusConflict || out["code"] != "billing.no_payment_method" {
		t.Errorf("without a card: %d %v", code, out)
	}
	f.card(t, owner)
	_, b := f.do(t, http.MethodGet, f.path("/billing"), owner, nil)
	if b["card"].(map[string]any)["last4"] != "4242" || b["auto_upgrade"] != true {
		t.Fatalf("after the card: %v", b)
	}
	code, b := f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-50"})
	if code != http.StatusOK || b["band"] != "team-50" || b["state"] != "active" || f.orgs.bands[f.org] != plan.Team50 {
		t.Fatalf("subscribe: %d %v", code, b)
	}
	// The provider says it is past due; the same event again changes nothing.
	cus := f.customer(t, owner)
	ev := provider.Event{ID: "evt_1", Type: provider.EventPaymentFailed, Customer: cus, Reason: "Declined."}
	f.srv.HandleEvent(context.Background(), ev)
	f.srv.HandleEvent(context.Background(), ev)
	if got := f.notices.kinds(); len(got) != 1 || got[0] != "payment_failed" {
		t.Errorf("one failure, once: %v", got)
	}
	if code, out := f.do(t, http.MethodGet, f.path("/billing/invoices"), owner, nil); code != http.StatusOK || len(out["invoices"].([]any)) != 1 {
		t.Errorf("invoices: %d %v", code, out)
	}
	// A plain user cannot see billing; a Billing Admin can but may not
	// touch automatic upgrade.
	if code, _ := f.do(t, http.MethodGet, f.path("/billing"), f.member(t, authz.User), nil); code != http.StatusForbidden {
		t.Errorf("a user: %d", code)
	}
	billing := f.member(t, authz.BillingAdmin)
	if code, _ := f.do(t, http.MethodGet, f.path("/billing"), billing, nil); code != http.StatusOK {
		t.Errorf("a billing admin reading: %d", code)
	}
	if code, _ := f.do(t, http.MethodPut, f.path("/billing/auto-upgrade"), billing, map[string]any{"on": false}); code != http.StatusForbidden {
		t.Errorf("a billing admin on automatic upgrade: %d", code)
	}
}

// The automatic upgrade story's "done when".
func TestAutomaticUpgrade(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	f.card(t, owner)
	f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-50"})
	f.notices.kinds()

	// 80% of the cap: one warning, not repeated as the count creeps.
	for _, n := range []int{40, 41, 42} {
		f.do(t, http.MethodPost, "/v1/internal/organizations/"+f.org.String()+"/members-changed", f.user, map[string]any{"members": n})
	}
	if got := f.notices.kinds(); len(got) != 1 || got[0] != "cap_warning" {
		t.Errorf("warning at 80%%: %v", got)
	}
	// The fifty-first member moves the org to team-200, and admins are told.
	code, out := f.do(t, http.MethodPost, "/v1/internal/organizations/"+f.org.String()+"/capacity", f.user, map[string]any{"members": 51})
	if code != http.StatusOK || out["band"] != "team-200" || out["upgraded"] != true || f.orgs.bands[f.org] != plan.Team200 {
		t.Fatalf("upgrade: %d %v", code, out)
	}
	if got := f.notices.kinds(); len(got) != 1 || got[0] != "auto_upgraded" {
		t.Errorf("upgrade email: %v", got)
	}
	// An import of 300 goes to team-500 in one step.
	if code, out := f.do(t, http.MethodPost, "/v1/internal/organizations/"+f.org.String()+"/capacity", f.user, map[string]any{"members": 300}); code != http.StatusOK || out["band"] != "team-500" {
		t.Errorf("one upgrade per crossing: %d %v", code, out)
	}
	// With automatic upgrade off, the cap refuses.
	if code, _ := f.do(t, http.MethodPut, f.path("/billing/auto-upgrade"), owner, map[string]any{"on": false}); code != http.StatusOK {
		t.Fatalf("turn off: %d", code)
	}
	if code, out := f.do(t, http.MethodPost, "/v1/internal/organizations/"+f.org.String()+"/capacity", f.user, map[string]any{"members": 501}); code != http.StatusConflict || out["code"] != plan.Code {
		t.Errorf("off: %d %v", code, out)
	}

	// A declined card leaves the plan where it was.
	g := newAPI(t)
	gowner := g.member(t, authz.Owner)
	g.card(t, gowner)
	g.do(t, http.MethodPut, g.path("/billing/band"), gowner, map[string]any{"band": "team-50"})
	g.pay.decline = true
	if code, _ := g.do(t, http.MethodPost, "/v1/internal/organizations/"+g.org.String()+"/capacity", g.user, map[string]any{"members": 51}); code != http.StatusConflict || g.orgs.bands[g.org] != plan.Team50 {
		t.Errorf("declined: %d %v", code, g.orgs.bands[g.org])
	}
}

// The dunning story: three emails over the grace, recovery with one, and
// the drop to free with nothing deleted.
func TestDunningAndTrial(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	f.card(t, owner)
	f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-50"})
	cus := f.customer(t, owner)
	f.notices.kinds()
	start := time.Now()
	f.srv.HandleEvent(context.Background(), provider.Event{ID: "evt_f1", Type: provider.EventPaymentFailed, Customer: cus, Reason: "Declined."})
	_, b := f.do(t, http.MethodGet, f.path("/billing"), owner, nil)
	if b["state"] != "past_due" || b["grace_days_left"].(float64) < 14 {
		t.Errorf("past due: %v", b)
	}
	f.clock.set(start.Add(7*24*time.Hour + time.Hour))
	f.srv.Tick(context.Background())
	f.srv.Tick(context.Background())
	f.clock.set(start.Add(12*24*time.Hour + time.Hour))
	f.srv.Tick(context.Background())
	if got := f.notices.kinds(); len(got) != 3 {
		t.Errorf("first failure, day 7, day 12: %v", got)
	}
	// The provider gives up: free, with the checklist.
	f.srv.HandleEvent(context.Background(), provider.Event{ID: "evt_del", Type: provider.EventSubscriptionDeleted, Customer: cus, Subscription: &provider.Subscription{}})
	if f.orgs.bands[f.org] != plan.Free || f.orgs.reasons[len(f.orgs.reasons)-1] != "payment_failure" {
		t.Errorf("dropped: %v %v", f.orgs.bands[f.org], f.orgs.reasons)
	}
	if got := f.notices.kinds(); len(got) != 1 || got[0] != "downgraded" {
		t.Errorf("checklist email: %v", got)
	}

	// Recovery: a successful payment clears it with one email.
	g := newAPI(t)
	gowner := g.member(t, authz.Owner)
	g.card(t, gowner)
	g.do(t, http.MethodPut, g.path("/billing/band"), gowner, map[string]any{"band": "team-50"})
	gcus := g.customer(t, gowner)
	g.srv.HandleEvent(context.Background(), provider.Event{ID: "evt_g1", Type: provider.EventPaymentFailed, Customer: gcus})
	g.srv.HandleEvent(context.Background(), provider.Event{ID: "evt_g2", Type: provider.EventPaymentSucceeded, Customer: gcus})
	if _, b := g.do(t, http.MethodGet, g.path("/billing"), gowner, nil); b["state"] != "active" {
		t.Errorf("recovered: %v", b)
	}
	if got := g.notices.kinds(); len(got) != 2 || got[1] != "payment_recovered" {
		t.Errorf("recovery email: %v", got)
	}

	// A trial with no card: reminders at day 10 and 13, free at day 14.
	h := newAPI(t)
	howner := h.member(t, authz.Owner)
	began := time.Now()
	if code, b := h.do(t, http.MethodPost, h.path("/billing/trial"), howner, nil); code != http.StatusOK || b["state"] != "trialing" || h.orgs.bands[h.org] != plan.Team50 {
		t.Fatalf("trial: %d %v", code, b)
	}
	if code, _ := h.do(t, http.MethodPost, h.path("/billing/trial"), howner, nil); code != http.StatusConflict {
		t.Errorf("a second trial: %d", code)
	}
	h.clock.set(began.Add(10*24*time.Hour + time.Hour))
	h.srv.Tick(context.Background())
	h.clock.set(began.Add(13*24*time.Hour + time.Hour))
	h.srv.Tick(context.Background())
	h.clock.set(began.Add(14*24*time.Hour + time.Hour))
	_, b = h.do(t, http.MethodGet, h.path("/billing"), howner, nil)
	if b["state"] != "free" || h.orgs.bands[h.org] != plan.Free || b["trial_available"] != false {
		t.Errorf("trial ended: %v", b)
	}
	if got := h.notices.kinds(); len(got) != 3 || got[2] != "trial_ended" {
		t.Errorf("trial emails: %v", got)
	}
}

// A voluntary downgrade waits for the period's end and can be cancelled.
func TestDowngrade(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	f.card(t, owner)
	f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-200"})
	code, b := f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-50"})
	if code != http.StatusOK || b["band"] != "team-200" || b["pending_band"] != "team-50" || f.orgs.bands[f.org] != plan.Team200 {
		t.Fatalf("scheduled: %d %v", code, b)
	}
	if code, out := f.do(t, http.MethodGet, f.path("/billing/band-preview?band=team-50"), owner, nil); code != http.StatusOK || out["applies"] != "period_end" {
		t.Errorf("preview down: %d %v", code, out)
	}
	code, b = f.do(t, http.MethodDelete, f.path("/billing/pending"), owner, nil)
	if code != http.StatusOK || b["pending_band"] != nil {
		t.Errorf("cancelled: %d %v", code, b)
	}
	// Enterprise is invoiced: no controls.
	f.orgs.bands[f.org] = plan.Enterprise
	if code, out := f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team-500"}); code != http.StatusConflict || out["code"] != "billing.invoiced" {
		t.Errorf("enterprise: %d %v", code, out)
	}
}
