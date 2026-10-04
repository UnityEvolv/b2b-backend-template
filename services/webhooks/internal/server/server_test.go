package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/server"
)

// keys is the organization service in miniature: one wrapped data key per
// org, made on first use.
type keys struct {
	wrapper kms.Wrapper
	mu      sync.Mutex
	byOrg   map[string]envelope.WrappedKey
}

func (k *keys) Current(ctx context.Context, org string) (envelope.WrappedKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if w, ok := k.byOrg[org]; ok {
		return w, nil
	}
	dataKey, err := envelope.NewDataKey()
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	wrapped, _, err := k.wrapper.Wrap(ctx, dataKey)
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	k.byOrg[org] = envelope.WrappedKey{OrgID: org, Version: 1, Wrapped: wrapped}
	return k.byOrg[org], nil
}

func (k *keys) Version(ctx context.Context, org string, _ uint32) (envelope.WrappedKey, error) {
	return k.Current(ctx, org)
}

// recorder keeps what was audited.
type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		out = append(out, e.Action)
	}
	return out
}

// receiver is a customer's endpoint: it keeps every request and answers
// with whatever status it is set to.
type receiver struct {
	*httptest.Server
	mu       sync.Mutex
	status   int
	requests []received
}

type received struct {
	header http.Header
	body   []byte
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{status: http.StatusOK}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests = append(r.requests, received{header: req.Header.Clone(), body: body})
		status := r.status
		r.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte("thanks, and here is something the platform must not keep"))
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) answer(status int) {
	r.mu.Lock()
	r.status = status
	r.mu.Unlock()
}

func (r *receiver) got() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.requests...)
}

// resolver answers names without DNS.
type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

type fixture struct {
	t        *testing.T
	pool     *pgxpool.Pool
	issuer   *stubissuer.Issuer
	srv      *server.Server
	api      *httptest.Server
	grants   authz.Static
	bands    plan.Static
	audit    *recorder
	clock    *clock
	pristine *server.Server // the same database, deployed: public addresses only
	papi     *httptest.Server
	keys     apiKeys
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type options struct {
	cap     ratelimit.Rule
	limiter *ratelimit.Limiter
}

func newFixture(t *testing.T, opts ...options) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("webhooks")
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrator, err := db.Migrator(stdlib.OpenDBFromPool(pool), service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}

	issuer, err := stubissuer.New("test", "b2bapp")
	if err != nil {
		t.Fatal(err)
	}
	keyring := apiKeys{}
	verifier := auth.NewStaticVerifier("test", "b2bapp", issuer.PublicKeys()).WithKeys(keyring)
	master, err := filekms.Open(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, pool: pool, issuer: issuer, keys: keyring, grants: authz.Static{}, bands: plan.Static{}, audit: &recorder{},
		clock: &clock{t: time.Now().UTC()}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := server.Deps{
		Cluster: db.SingleShard(pool), Logger: logger, Authz: f.grants, Plans: f.bands,
		Keys:  envelope.New(&keys{wrapper: master, byOrg: map[string]envelope.WrappedKey{}}, master),
		Audit: f.audit,
		Resolver: resolver{
			"hooks.example.com":    {netip.MustParseAddr("93.184.216.34")},
			"internal.example.com": {netip.MustParseAddr("10.0.0.7")},
		},
	}
	for _, o := range opts {
		deps.Limiter, deps.EventCap = o.limiter, o.cap
	}
	serve := func(s *server.Server) *httptest.Server {
		h := httptest.NewServer(httpx.Logged(logger, auth.Require(verifier, s.Handler(httpx.NewMux()))))
		t.Cleanup(h.Close)
		return h
	}
	f.srv = server.New(deps, server.Config{Local: true, Product: "Test"})
	f.srv.WithClock(f.clock.now)
	f.api = serve(f.srv)
	f.pristine = server.New(deps, server.Config{})
	f.papi = serve(f.pristine)
	t.Cleanup(f.srv.Wait)
	return f
}

const (
	orgA = "01922b5e-0000-7000-8000-0000000000a1"
	orgB = "01922b5e-0000-7000-8000-0000000000b1"
)

// admin is an Admin of org on a plan with webhooks.
func (f *fixture) admin(org string) string {
	f.bands[org] = "team"
	return f.as(org, authz.Admin, authz.Defaults())
}

func (f *fixture) as(org string, role authz.Role, c authz.Config) string {
	m := uuid.NewString()
	f.grants[org+"/"+m] = authz.Grant{Role: role, Permissions: authz.Effective(role, c)}
	return f.token(auth.Caller{UserID: uuid.NewString(), OrgID: org, MembershipID: m})
}

func (f *fixture) token(c auth.Caller) string {
	raw, err := f.issuer.Issue(c, time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) service(name string) string { return f.token(auth.Caller{Service: name}) }

func (f *fixture) do(base, method, path, token string, body any) (int, map[string]any) {
	f.t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, base+path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (f *fixture) call(method, path, token string, body any) (int, map[string]any) {
	f.t.Helper()
	return f.do(f.api.URL, method, path, token, body)
}

func endpoints(org string) string { return "/v1/organizations/" + org + "/webhook-endpoints" }

// create adds an endpoint at url and answers its id and secret.
func (f *fixture) create(org, token, url string, types ...string) (string, string) {
	f.t.Helper()
	body := map[string]any{"url": url}
	if len(types) > 0 {
		body["event_types"] = types
	}
	status, out := f.call(http.MethodPost, endpoints(org), token, body)
	if status != http.StatusCreated {
		f.t.Fatalf("create: %d %v", status, out)
	}
	return out["endpoint"].(map[string]any)["id"].(string), out["secret"].(string)
}

// emit sends an event as the audit service would, and waits for the
// attempts it set off.
func (f *fixture) emit(org string, body map[string]any) (int, map[string]any) {
	f.t.Helper()
	status, out := f.call(http.MethodPost, "/v1/internal/organizations/"+org+"/events", f.service("audit"), body)
	f.srv.Wait()
	return status, out
}

func (f *fixture) deliveries(org, token, query string) []map[string]any {
	f.t.Helper()
	status, out := f.call(http.MethodGet, "/v1/organizations/"+org+"/webhook-deliveries"+query, token, nil)
	if status != http.StatusOK {
		f.t.Fatalf("deliveries: %d %v", status, out)
	}
	var list []map[string]any
	for _, d := range out["deliveries"].([]any) {
		list = append(list, d.(map[string]any))
	}
	return list
}

func added(membership string) map[string]any {
	return map[string]any{"type": "member.added", "data": map[string]any{"membership_id": membership, "user_id": uuid.NewString(), "role": "user"}}
}

// An admin adds, reads, changes and removes an endpoint. Its secret is
// shown once, kept sealed under the org's key, and never read back; every
// change is audited.
func TestEndpointLifecycle(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	rcv := newReceiver(t)
	id, secret := f.create(orgA, admin, rcv.URL+"/hooks", "member.added", "member.added")
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret %q", secret)
	}
	status, got := f.call(http.MethodGet, endpoints(orgA)+"/"+id, admin, nil)
	if status != http.StatusOK || got["url"] != rcv.URL+"/hooks" || got["enabled"] != true || len(got["event_types"].([]any)) != 1 {
		t.Fatalf("get: %d %v", status, got)
	}
	if _, ok := got["secret"]; ok {
		t.Error("the secret was read back")
	}
	var sealed []byte
	if err := f.pool.QueryRow(context.Background(), "SELECT secret FROM endpoints WHERE org_id = $1 AND id = $2", orgA, id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	key, _ := webhook.ParseSecret(secret)
	if bytes.Contains(sealed, key) || bytes.Contains(sealed, []byte(secret)) {
		t.Error("the secret is stored in the clear")
	}

	status, got = f.call(http.MethodPatch, endpoints(orgA)+"/"+id, admin, map[string]any{"event_types": []string{}, "enabled": false, "description": "CRM sync"})
	if status != http.StatusOK || got["enabled"] != false || got["description"] != "CRM sync" || len(got["event_types"].([]any)) != 0 || got["url"] != rcv.URL+"/hooks" {
		t.Fatalf("update: %d %v", status, got)
	}
	if status, got = f.call(http.MethodPatch, endpoints(orgA)+"/"+id, admin, map[string]any{"event_types": []string{"nope.nope"}}); status != http.StatusBadRequest {
		t.Errorf("unregistered type: %d %v", status, got)
	}
	status, got = f.call(http.MethodGet, endpoints(orgA), admin, nil)
	if status != http.StatusOK || len(got["endpoints"].([]any)) != 1 {
		t.Fatalf("list: %d %v", status, got)
	}
	if status, _ = f.call(http.MethodDelete, endpoints(orgA)+"/"+id, admin, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if status, _ = f.call(http.MethodGet, endpoints(orgA)+"/"+id, admin, nil); status != http.StatusNotFound {
		t.Errorf("deleted endpoint: %d", status)
	}
	want := []string{"webhooks.endpoint.created", "webhooks.endpoint.updated", "webhooks.endpoint.deleted"}
	if got := f.audit.actions(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audited %v, want %v", got, want)
	}
}

// The webhooks permission gates every admin endpoint, through the
// authorization service; the plan's webhooks feature gates adding one.
func TestPermissionAndPlanGates(t *testing.T) {
	f := newFixture(t)
	rcv := newReceiver(t)
	f.bands[orgA] = "team"
	user := f.as(orgA, authz.User, authz.Defaults())
	if status, out := f.call(http.MethodGet, endpoints(orgA), user, nil); status != http.StatusForbidden || out["code"] != "forbidden" {
		t.Errorf("a User lists: %d %v", status, out)
	}
	// An Owner who took webhooks from Admins: the Admin is refused.
	without := authz.Config{Admin: []authz.Permission{authz.Users, authz.Audit, authz.SSO}}
	admin := f.as(orgA, authz.Admin, without)
	if status, _ := f.call(http.MethodPost, endpoints(orgA), admin, map[string]any{"url": rcv.URL}); status != http.StatusForbidden {
		t.Errorf("an Admin without webhooks creates: %d", status)
	}
	// Another org's token reaches nothing here.
	other := f.admin(orgB)
	if status, _ := f.call(http.MethodGet, endpoints(orgA), other, nil); status != http.StatusForbidden {
		t.Errorf("another org's admin lists: %d", status)
	}

	// On free, the feature is refused with the plan to move to.
	f.bands[orgA] = "free"
	owner := f.as(orgA, authz.Owner, authz.Defaults())
	status, out := f.call(http.MethodPost, endpoints(orgA), owner, map[string]any{"url": rcv.URL})
	if status != http.StatusForbidden || out["code"] != plan.Code || out["fields"].(map[string]any)["required_plan"] != "team" {
		t.Fatalf("free plan creates: %d %v", status, out)
	}
	status, out = f.call(http.MethodGet, "/v1/organizations/"+orgA+"/webhook-event-types", owner, nil)
	if status != http.StatusOK || out["available"] != false || out["required_plan"] != "team" || len(out["event_types"].([]any)) < 3 {
		t.Errorf("event types on free: %d %v", status, out)
	}
	// Moved up, the next request is allowed: nothing cached.
	f.bands[orgA] = "team"
	if status, out := f.call(http.MethodPost, endpoints(orgA), owner, map[string]any{"url": rcv.URL}); status != http.StatusCreated {
		t.Errorf("team plan creates: %d %v", status, out)
	}
	// Downgraded with an endpoint in place: nothing is delivered.
	f.bands[orgA] = "free"
	if status, out := f.emit(orgA, added(uuid.NewString())); status != http.StatusAccepted || out["deliveries"] != float64(0) {
		t.Errorf("emit on free: %d %v", status, out)
	}
	if n := len(rcv.got()); n != 0 {
		t.Errorf("%d deliveries on a plan without webhooks", n)
	}
}

// Deployed, an endpoint is https on a public address; a private, local or
// reserved one is refused when it is saved, and again at the connection.
func TestPrivateAddressesAreRefused(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	for _, url := range []string{
		"https://10.0.0.1/hook", "https://127.0.0.1:8443/hook", "https://[::1]/hook", "https://169.254.169.254/latest",
		"https://localhost/hook", "https://internal.example.com/hook", "http://hooks.example.com/hook",
		"https://user:pass@hooks.example.com/hook", "hooks.example.com/hook", "",
	} {
		status, out := f.do(f.papi.URL, http.MethodPost, endpoints(orgA), admin, map[string]any{"url": url})
		if status != http.StatusBadRequest || out["fields"].(map[string]any)["url"] == nil {
			t.Errorf("%q: %d %v", url, status, out)
		}
	}
	if status, out := f.do(f.papi.URL, http.MethodPost, endpoints(orgA), admin, map[string]any{"url": "https://hooks.example.com/hook"}); status != http.StatusCreated {
		t.Errorf("a public https endpoint: %d %v", status, out)
	}

	// A name that resolved to a public address when saved and to a private
	// one now is refused at the connection, and the delivery says so.
	rcv := newReceiver(t)
	id, _ := f.create(orgA, admin, rcv.URL)
	status, out := f.do(f.papi.URL, http.MethodPost, endpoints(orgA)+"/"+id+"/test", admin, nil)
	if status != http.StatusOK || out["status"] == "succeeded" || out["last_error"] != "The endpoint's address is not public." {
		t.Errorf("deployed test to a loopback receiver: %d %v", status, out)
	}
	if n := len(rcv.got()); n != 0 {
		t.Errorf("the loopback receiver got %d requests", n)
	}
}

// An event reaches every endpoint subscribed to its type, signed, with its
// id in webhook-id, and its delivery is recorded with the endpoint's
// status and latency. The same id again is the same event.
func TestEventsAreDeliveredSignedAndRecorded(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	all, removed := newReceiver(t), newReceiver(t)
	allID, secret := f.create(orgA, admin, all.URL)
	f.create(orgA, admin, removed.URL, "member.removed")
	off, _ := f.create(orgA, admin, newReceiver(t).URL)
	if status, _ := f.call(http.MethodPatch, endpoints(orgA)+"/"+off, admin, map[string]any{"enabled": false}); status != http.StatusOK {
		t.Fatal("disable")
	}

	membership := uuid.NewString()
	event := added(membership)
	event["id"] = uuid.NewString()
	status, out := f.emit(orgA, event)
	if status != http.StatusAccepted || out["deliveries"] != float64(1) || out["id"] != event["id"] {
		t.Fatalf("emit: %d %v", status, out)
	}
	got := all.got()
	if len(got) != 1 || len(removed.got()) != 0 {
		t.Fatalf("delivered %d to all, %d to member.removed", len(got), len(removed.got()))
	}
	r := got[0]
	if err := webhook.Verify(secret, r.header, r.body, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.header.Get("webhook-id") != event["id"] || r.header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.header.Get("User-Agent"), "Test-Webhooks/") {
		t.Errorf("headers %v", r.header)
	}
	var p webhook.Payload
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatal(err)
	}
	if p.ID != event["id"] || p.Type != webhook.MemberAdded || p.OrgID != orgA || p.Data["membership_id"] != membership {
		t.Errorf("payload %+v", p)
	}

	list := f.deliveries(orgA, admin, "?endpoint_id="+allID)
	if len(list) != 1 {
		t.Fatalf("deliveries %v", list)
	}
	d := list[0]
	if d["status"] != "succeeded" || d["attempts"] != float64(1) || d["last_status_code"] != float64(200) || d["last_latency_ms"] == nil || d["event_type"] != "member.added" || d["next_attempt_at"] != nil {
		t.Errorf("delivery %v", d)
	}
	status, detail := f.call(http.MethodGet, "/v1/organizations/"+orgA+"/webhook-deliveries/"+d["id"].(string), admin, nil)
	if status != http.StatusOK || len(detail["attempt_log"].([]any)) != 1 || detail["payload"].(map[string]any)["id"] != event["id"] {
		t.Errorf("detail %d %v", status, detail)
	}

	// The same id again: one event, nothing sent twice.
	if status, out := f.emit(orgA, event); status != http.StatusAccepted || out["deliveries"] != float64(0) {
		t.Errorf("repeat: %d %v", status, out)
	}
	if len(all.got()) != 1 {
		t.Error("a repeated event was delivered again")
	}
	// Another org's deliveries are its own.
	if list := f.deliveries(orgB, f.admin(orgB), ""); len(list) != 0 {
		t.Errorf("org B sees %v", list)
	}
}

// Event data carries ids: a name or an email is refused, as is a type
// nobody registered, and only a service may send.
func TestEventsCarryNoPersonalData(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	rcv := newReceiver(t)
	f.create(orgA, admin, rcv.URL)
	for _, data := range []map[string]any{
		{"membership_id": "m", "email": "ada@example.com"},
		{"membership_id": "m", "note": "ada@example.com joined"},
		{"user": map[string]any{"name": "Ada"}},
	} {
		status, out := f.emit(orgA, map[string]any{"type": "member.added", "data": data})
		if status != http.StatusBadRequest || out["code"] != "webhooks.personal_data" {
			t.Errorf("%v: %d %v", data, status, out)
		}
	}
	if status, out := f.emit(orgA, map[string]any{"type": "project.created", "data": map[string]any{}}); status != http.StatusBadRequest || out["code"] != "invalid_request" {
		t.Errorf("unregistered type: %d %v", status, out)
	}
	if status, _ := f.call(http.MethodPost, "/v1/internal/organizations/"+orgA+"/events", admin, added("m")); status != http.StatusForbidden {
		t.Errorf("a person sends: %d", status)
	}
	if n := len(rcv.got()); n != 0 {
		t.Errorf("%d refused events delivered", n)
	}
	// What the core derives from the audit log is ids only.
	_, data, _ := webhook.FromAudit(webhook.AuditEntry{Action: "membership.created", TargetID: "m", Actor: "membership:x",
		Details: map[string]any{"user_id": "u", "role": "user", "email": "ada@example.com", "name": "Ada"}})
	raw, _ := json.Marshal(data)
	if strings.Contains(string(raw), "ada") || strings.Contains(strings.ToLower(string(raw)), "@") {
		t.Errorf("core event data %s", raw)
	}
}

// A failed delivery stays a row: the sweep tries it again once its backoff
// has passed, and gives up after the sixth attempt. An admin can still
// resend it, and a delivery whose endpoint recovers succeeds on the next
// sweep.
func TestRetrySweepRedeliversAndGivesUp(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	rcv := newReceiver(t)
	rcv.answer(http.StatusInternalServerError)
	f.create(orgA, admin, rcv.URL)
	if status, _ := f.emit(orgA, added("m1")); status != http.StatusAccepted {
		t.Fatal("emit")
	}
	d := f.deliveries(orgA, admin, "")[0]
	if d["status"] != "pending" || d["attempts"] != float64(1) || d["last_status_code"] != float64(500) || d["last_error"] != "The endpoint answered 500." {
		t.Fatalf("after the first attempt: %v", d)
	}
	next, _ := time.Parse(time.RFC3339Nano, d["next_attempt_at"].(string))
	if wait := next.Sub(f.clock.now()); wait < 4*time.Minute || wait > 6*time.Minute {
		t.Errorf("first retry in %s, want about 5 minutes", wait)
	}
	// Not yet due: the sweep leaves it.
	if n, err := f.srv.Sweep(context.Background()); err != nil || n != 0 {
		t.Fatalf("early sweep: %d %v", n, err)
	}
	for attempt := 2; attempt <= server.MaxAttempts; attempt++ {
		f.clock.add(25 * time.Hour)
		if n, err := f.srv.Sweep(context.Background()); err != nil || n != 1 {
			t.Fatalf("sweep %d: %d %v", attempt, n, err)
		}
	}
	d = f.deliveries(orgA, admin, "")[0]
	if d["status"] != "failed" || d["attempts"] != float64(server.MaxAttempts) || d["next_attempt_at"] != nil {
		t.Fatalf("after giving up: %v", d)
	}
	if n := len(rcv.got()); n != server.MaxAttempts {
		t.Errorf("%d requests, want %d", n, server.MaxAttempts)
	}
	f.clock.add(48 * time.Hour)
	if n, _ := f.srv.Sweep(context.Background()); n != 0 {
		t.Error("the sweep retried a delivery that gave up")
	}
	if list := f.deliveries(orgA, admin, "?status=failed"); len(list) != 1 {
		t.Errorf("failed filter: %v", list)
	}

	// The endpoint is fixed; an admin resends, and it goes.
	rcv.answer(http.StatusNoContent)
	status, out := f.call(http.MethodPost, "/v1/organizations/"+orgA+"/webhook-deliveries/"+d["id"].(string)+"/resend", admin, nil)
	if status != http.StatusOK || out["status"] != "succeeded" || out["last_status_code"] != float64(204) {
		t.Fatalf("resend: %d %v", status, out)
	}
	log := out["attempt_log"].([]any)
	if len(log) != server.MaxAttempts+1 || log[len(log)-1].(map[string]any)["manual"] != true {
		t.Errorf("attempt log %v", log)
	}
	got := rcv.got()
	if got[0].header.Get("webhook-id") != got[len(got)-1].header.Get("webhook-id") {
		t.Error("a resend changed the webhook-id")
	}

	// A delivery that fails once and then finds the endpoint back.
	rcv.answer(http.StatusBadGateway)
	f.emit(orgA, added("m2"))
	rcv.answer(http.StatusOK)
	f.clock.add(10 * time.Minute)
	if n, err := f.srv.Sweep(context.Background()); err != nil || n != 1 {
		t.Fatalf("recovery sweep: %d %v", n, err)
	}
	if d := f.deliveries(orgA, admin, "")[0]; d["status"] != "succeeded" || d["attempts"] != float64(2) {
		t.Errorf("recovered: %v", d)
	}
	if !strings.Contains(strings.Join(f.audit.actions(), ","), "webhooks.delivery.resent") {
		t.Error("the resend was not audited")
	}
}

// A rotation gives a new secret, shown once. For the overlap every
// delivery carries a signature under the new secret and the old one, so a
// receiver on either verifies; after it, only the new.
func TestSecretRotationOverlaps(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	rcv := newReceiver(t)
	id, old := f.create(orgA, admin, rcv.URL)
	status, out := f.call(http.MethodPost, endpoints(orgA)+"/"+id+"/rotate-secret", admin, map[string]any{"overlap_hours": 24})
	if status != http.StatusOK {
		t.Fatalf("rotate: %d %v", status, out)
	}
	fresh := out["secret"].(string)
	if fresh == old || out["endpoint"].(map[string]any)["previous_secret_expires_at"] == nil {
		t.Fatalf("rotated: %v", out)
	}
	f.emit(orgA, added("m1"))
	r := rcv.got()[0]
	if n := len(strings.Fields(r.header.Get("webhook-signature"))); n != 2 {
		t.Fatalf("%d signatures during the overlap", n)
	}
	for _, s := range []string{old, fresh} {
		if err := webhook.Verify(s, r.header, r.body, f.clock.now()); err != nil {
			t.Errorf("verify during the overlap: %v", err)
		}
	}

	f.clock.add(25 * time.Hour)
	f.emit(orgA, added("m2"))
	r = rcv.got()[1]
	if n := len(strings.Fields(r.header.Get("webhook-signature"))); n != 1 {
		t.Errorf("%d signatures after the overlap", n)
	}
	if err := webhook.Verify(fresh, r.header, r.body, f.clock.now()); err != nil {
		t.Errorf("new secret after the overlap: %v", err)
	}
	if err := webhook.Verify(old, r.header, r.body, f.clock.now()); err == nil {
		t.Error("the old secret still verifies after the overlap")
	}
	if err := f.srv.Housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, ep := f.call(http.MethodGet, endpoints(orgA)+"/"+id, admin, nil)
	if ep["previous_secret_expires_at"] != nil {
		t.Errorf("the old secret is still kept: %v", ep)
	}

	// Rotating with no overlap ends the old secret at once.
	_, out = f.call(http.MethodPost, endpoints(orgA)+"/"+id+"/rotate-secret", admin, map[string]any{"overlap_hours": 0})
	third := out["secret"].(string)
	f.emit(orgA, added("m3"))
	r = rcv.got()[2]
	if n := len(strings.Fields(r.header.Get("webhook-signature"))); n != 1 || webhook.Verify(third, r.header, r.body, f.clock.now()) != nil {
		t.Errorf("no-overlap rotation: %v", r.header)
	}
	if status, _ := f.call(http.MethodPost, endpoints(orgA)+"/"+id+"/rotate-secret", admin, map[string]any{"overlap_hours": 1000}); status != http.StatusBadRequest {
		t.Errorf("a week and more of overlap: %d", status)
	}
	if n := strings.Count(strings.Join(f.audit.actions(), ","), "webhooks.endpoint.secret_rotated"); n != 2 {
		t.Errorf("%d rotations audited", n)
	}
}

// A test event goes to the one endpoint asked, whatever it subscribes to,
// and the answer says how it went.
func TestSendATestEvent(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	rcv := newReceiver(t)
	id, secret := f.create(orgA, admin, rcv.URL, "member.removed")
	status, out := f.call(http.MethodPost, endpoints(orgA)+"/"+id+"/test", admin, nil)
	if status != http.StatusOK || out["status"] != "succeeded" || out["event_type"] != "webhook.test" || len(out["attempt_log"].([]any)) != 1 {
		t.Fatalf("test: %d %v", status, out)
	}
	r := rcv.got()[0]
	if err := webhook.Verify(secret, r.header, r.body, time.Now()); err != nil {
		t.Errorf("verify: %v", err)
	}
	if status, _ := f.call(http.MethodPost, endpoints(orgA)+"/"+uuid.NewString()+"/test", admin, nil); status != http.StatusNotFound {
		t.Errorf("unknown endpoint: %d", status)
	}
}

// One org's activity cannot make the platform send without end: past its
// cap, an event is refused and the sender told.
func TestEventsAreCappedPerOrg(t *testing.T) {
	url := redisURL(t)
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := ratelimit.New(rdb, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f := newFixture(t, options{limiter: limiter, cap: ratelimit.Rule{Name: "webhook-events-test-" + uuid.NewString()[:8], Limit: 3, Window: time.Hour}})
	admin := f.admin(orgA)
	f.create(orgA, admin, newReceiver(t).URL)
	for i := range 3 {
		if status, out := f.emit(orgA, added(uuid.NewString())); status != http.StatusAccepted {
			t.Fatalf("event %d: %d %v", i, status, out)
		}
	}
	if status, out := f.emit(orgA, added(uuid.NewString())); status != http.StatusTooManyRequests || out["code"] != "rate_limited" {
		t.Errorf("over the cap: %d %v", status, out)
	}
}

func redisURL(t *testing.T) string {
	t.Helper()
	if u := strings.TrimSpace(os.Getenv("TEST_REDIS_URL")); u != "" {
		return u
	}
	t.Skip("TEST_REDIS_URL is not set")
	return ""
}

// As a data owner: the org export holds its endpoints, events, deliveries
// and attempts, never a secret; the purge empties the org and leaves the
// next alone. Both are the organization service's only.
func TestExportAndPurgeAsADataOwner(t *testing.T) {
	f := newFixture(t)
	a, b := f.admin(orgA), f.admin(orgB)
	f.create(orgA, a, newReceiver(t).URL)
	f.create(orgB, b, newReceiver(t).URL)
	f.emit(orgA, added("m1"))
	f.emit(orgB, added("m2"))

	data := "/v1/internal/organizations/" + orgA + "/data"
	if status, _ := f.call(http.MethodGet, data, f.service("billing"), nil); status != http.StatusForbidden {
		t.Errorf("billing exports: %d", status)
	}
	status, part := f.call(http.MethodGet, data, f.service("organization"), nil)
	if status != http.StatusOK || part["service"] != "webhooks" {
		t.Fatalf("export: %d %v", status, part)
	}
	body := part["data"].(map[string]any)
	for _, k := range []string{"endpoints", "events", "deliveries", "attempts"} {
		if n := len(body[k].([]any)); n != 1 {
			t.Errorf("export %s: %d rows", k, n)
		}
	}
	raw, _ := json.Marshal(part)
	if strings.Contains(string(raw), `"secret"`) || strings.Contains(string(raw), "previous_secret\"") {
		t.Errorf("a secret in the export: %s", raw)
	}
	status, user := f.call(http.MethodGet, "/v1/internal/users/"+uuid.NewString()+"/data", f.service("organization"), nil)
	if status != http.StatusOK || user["service"] != "webhooks" {
		t.Errorf("user export: %d %v", status, user)
	}

	if status, _ := f.call(http.MethodDelete, data, f.service("user"), nil); status != http.StatusForbidden {
		t.Errorf("user purges: %d", status)
	}
	for range 2 { // idempotent
		status, out := f.call(http.MethodDelete, data, f.service("organization"), nil)
		if status != http.StatusOK || out["remaining"] != float64(0) {
			t.Fatalf("purge: %d %v", status, out)
		}
	}
	if list := f.deliveries(orgB, b, ""); len(list) != 1 {
		t.Errorf("org B after A's purge: %v", list)
	}
}

// The schema follows the table conventions: org_id leading every key, the
// provenance columns and trigger, the right types.
func TestTablesFollowTheConventions(t *testing.T) {
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("webhooks")
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	migrator, err := db.Migrator(stdlib.OpenDBFromPool(pool), service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}
	problems, err := db.CheckConventions(ctx, pool, service.Schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// apiKeys is the identity service's key resolution in miniature: a raw
// key to what it is.
type apiKeys map[string]auth.Key

func (k apiKeys) Resolve(_ context.Context, raw string) (auth.Key, error) {
	if key, ok := k[raw]; ok {
		return key, nil
	}
	return auth.Key{}, auth.ErrUnauthenticated
}

// key is a fresh org API key for org, granted groups.
func (f *fixture) key(org string, groups ...string) string {
	raw := "test_ak_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.keys[raw] = auth.Key{ID: uuid.NewString(), Kind: auth.OrgKey, OrgID: org, Groups: groups}
	return raw
}

// An org's API key granted the webhooks group manages the org's endpoints
// through authz.Require, as an Admin would, and acts as itself; one without
// the group, or for another org, is refused. The plan gate still holds.
func TestAnAPIKeyWithTheWebhooksGroupManagesEndpoints(t *testing.T) {
	f := newFixture(t)
	f.bands[orgA] = "team"
	rcv := newReceiver(t)
	key := f.key(orgA, "webhooks")
	id, secret := f.create(orgA, key, rcv.URL)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret %q", secret)
	}
	if status, out := f.call(http.MethodGet, endpoints(orgA), key, nil); status != http.StatusOK || len(out["endpoints"].([]any)) != 1 {
		t.Errorf("list with a key: %d %v", status, out)
	}
	if status, out := f.call(http.MethodPost, endpoints(orgA)+"/"+id+"/test", key, nil); status != http.StatusOK || out["status"] != "succeeded" {
		t.Errorf("test with a key: %d %v", status, out)
	}
	var by string
	if err := f.pool.QueryRow(context.Background(), "SELECT created_by FROM endpoints WHERE org_id = $1 AND id = $2", orgA, id).Scan(&by); err != nil || !strings.HasPrefix(by, "api_key:") {
		t.Errorf("created by %q (%v), want the key", by, err)
	}

	without := f.key(orgA, "users")
	if status, out := f.call(http.MethodGet, endpoints(orgA), without, nil); status != http.StatusForbidden || out["code"] != "forbidden" {
		t.Errorf("a key without webhooks: %d %v", status, out)
	}
	other := f.key(orgB, "webhooks")
	f.bands[orgB] = "team"
	if status, _ := f.call(http.MethodGet, endpoints(orgA), other, nil); status != http.StatusForbidden {
		t.Errorf("another org's key: %d", status)
	}
	if status, _ := f.call(http.MethodPost, "/v1/internal/organizations/"+orgA+"/events", key, added("m")); status != http.StatusForbidden {
		t.Errorf("a key sends an event: %d", status)
	}
	f.bands[orgA] = "free"
	if status, out := f.call(http.MethodPost, endpoints(orgA), key, map[string]any{"url": rcv.URL}); status != http.StatusForbidden || out["code"] != plan.Code {
		t.Errorf("a key on a plan without webhooks: %d %v", status, out)
	}
}
