package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/oidc"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/server"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/signer"
)

var (
	acme   = uuid.MustParse("01922b5e-0000-7000-8000-0000000000a1")
	globex = uuid.MustParse("01922b5e-0000-7000-8000-0000000000b2")
)

// fakeIdP is two OpenID providers on one server, sharing a key: one shaped
// like an Entra tenant (issuer /tenant/v2.0, the address in
// preferred_username, credentials in the form, keys without alg) and one
// shaped like Google (issuer /google, email_verified and hd, credentials by
// HTTP basic authentication). Each has discovery, keys, and a token endpoint
// that issues an identity token for whoever the test says signed in.
type fakeIdP struct {
	srv      *httptest.Server
	key      jwk.Key
	public   jwk.Set
	clientID string
	secret   string

	mu    sync.Mutex
	codes map[string]fakeGrant // code => who, for which issuer
	seen  []url.Values         // token requests
}

type fakeGrant struct {
	who    person
	nonce  string
	google bool
}

type person struct {
	sub, email, name, department string
	// unverified sends email_verified=false; hd is Google's hosted domain.
	unverified bool
	hd         string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := jwk.Import(raw)
	_ = key.Set(jwk.KeyIDKey, "idp-1")
	set := jwk.NewSet()
	_ = set.AddKey(key)
	public, _ := jwk.PublicSetOf(set)
	f := &fakeIdP{key: key, public: public, clientID: "client-1", secret: "shh", codes: map[string]fakeGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tenant/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.tenantIssuer(), "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys",
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		})
	})
	mux.HandleFunc("GET /google/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.googleIssuer(), "authorization_endpoint": f.srv.URL + "/google/authorize",
			"token_endpoint": f.srv.URL + "/google/token", "jwks_uri": f.srv.URL + "/keys",
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(f.public) })
	token := func(google bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			f.mu.Lock()
			f.seen = append(f.seen, r.PostForm)
			g, ok := f.codes[r.PostForm.Get("code")]
			delete(f.codes, r.PostForm.Get("code"))
			f.mu.Unlock()
			id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
			if google {
				id, secret, _ = r.BasicAuth()
			}
			if id != f.clientID || secret != f.secret {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
				return
			}
			if !ok || g.google != google || r.PostForm.Get("code_verifier") == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			b := jwt.NewBuilder().Audience([]string{f.clientID}).Subject(g.who.sub).
				IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).
				Claim("nonce", g.nonce).Claim("name", g.who.name)
			if google {
				b = b.Issuer(f.googleIssuer()).Claim("email", g.who.email).Claim("email_verified", !g.who.unverified)
				if g.who.hd != "" {
					b = b.Claim("hd", g.who.hd)
				}
			} else {
				b = b.Issuer(f.tenantIssuer()).Claim("preferred_username", g.who.email).Claim("department", g.who.department)
			}
			tok, _ := b.Build()
			signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), f.key))
			json.NewEncoder(w).Encode(map[string]any{"id_token": string(signed), "access_token": "x", "token_type": "Bearer"})
		}
	}
	mux.HandleFunc("POST /token", token(false))
	mux.HandleFunc("POST /google/token", token(true))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize is the browser at the provider: the person signs in and a code
// is minted for the nonce the request carried.
func (f *fakeIdP) authorize(t *testing.T, location string, who person) (code, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	google := strings.HasPrefix(location, f.srv.URL+"/google/authorize")
	if !google && !strings.HasPrefix(location, f.srv.URL+"/authorize") || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("nonce") == "" {
		t.Fatalf("not an authorize request with PKCE and a nonce: %s", location)
	}
	code = uuid.NewString()
	f.mu.Lock()
	f.codes[code] = fakeGrant{who: who, nonce: u.Query().Get("nonce"), google: google}
	f.mu.Unlock()
	return code, u.Query().Get("state")
}

func (f *fakeIdP) tenantIssuer() string { return f.srv.URL + "/tenant/v2.0" }
func (f *fakeIdP) googleIssuer() string { return f.srv.URL + "/google" }

// fakeUsers is the user service in memory.
type fakeUsers struct {
	mu          sync.Mutex
	users       map[string]uuid.UUID // email => id
	memberships []server.Membership
	inactive    map[string]bool // email@org => refuse
	activity    []uuid.UUID
	capped      map[uuid.UUID]bool // orgs at their plan's user limit
	created     []server.NewMembership
	signedIn    []uuid.UUID
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{users: map[string]uuid.UUID{}, inactive: map[string]bool{}, capped: map[uuid.UUID]bool{}}
}

func (u *fakeUsers) RecordSignIn(_ context.Context, in server.SignIn) (server.SignInResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.inactive[in.Email+"@"+in.OrgID.String()] {
		return server.SignInResult{}, &server.Refusal{Status: 409, Code: "membership.inactive"}
	}
	id, ok := u.users[in.Email]
	if !ok {
		id = uuid.New()
		u.users[in.Email] = id
	}
	var out server.SignInResult
	out.User.ID = id
	found := false
	for i := range u.memberships {
		if u.memberships[i].User.ID == id && u.memberships[i].OrgID == in.OrgID {
			found = true
			out.Membership = u.memberships[i]
		}
	}
	if !found {
		m := server.Membership{ID: uuid.New(), OrgID: in.OrgID, Status: "active", Role: "user", Source: "idp"}
		m.User.ID = id
		u.memberships = append(u.memberships, m)
		out.Membership = m
	}
	out.Memberships = u.of(id)
	return out, nil
}

func (u *fakeUsers) of(id uuid.UUID) []server.Membership {
	var out []server.Membership
	for _, m := range u.memberships {
		if m.User.ID == id {
			out = append(out, m)
		}
	}
	return out
}

func (u *fakeUsers) ListMemberships(_ context.Context, userID uuid.UUID) ([]server.Membership, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.of(userID), nil
}

func (u *fakeUsers) RecordActivity(_ context.Context, _ uuid.UUID, membershipID uuid.UUID) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.activity = append(u.activity, membershipID)
	return nil
}

// add is a membership made some other way (an invite), with a last activity.
func (u *fakeUsers) add(email string, org uuid.UUID, status string, lastActive *time.Time) server.Membership {
	u.mu.Lock()
	defer u.mu.Unlock()
	id, ok := u.users[email]
	if !ok {
		id = uuid.New()
		u.users[email] = id
	}
	m := server.Membership{ID: uuid.New(), OrgID: org, Status: status, Role: "user", Source: "invite", LastActiveAt: lastActive}
	m.User.ID = id
	u.memberships = append(u.memberships, m)
	return m
}

type fakeOrgs map[string]uuid.UUID

func (o fakeOrgs) ByDomain(_ context.Context, domain string) (uuid.UUID, error) {
	if id, ok := o[domain]; ok {
		return id, nil
	}
	return uuid.Nil, server.ErrNotFound
}

// Status is suspended for an org the test suspended with the key
// "suspended:<org id>", and closing, to be deleted on closingDate, for one
// it closed with "closing:<org id>".
func (o fakeOrgs) Status(_ context.Context, orgID uuid.UUID) (server.OrgStatus, error) {
	if _, ok := o["suspended:"+orgID.String()]; ok {
		return server.OrgStatus{Status: "suspended"}, nil
	}
	if _, ok := o["closing:"+orgID.String()]; ok {
		d := closingDate
		return server.OrgStatus{Status: "closing", PurgeAfter: &d}, nil
	}
	return server.OrgStatus{Status: "active"}, nil
}

// closingDate is when a closing org in these tests is deleted.
var closingDate = time.Date(2030, time.March, 4, 0, 0, 0, 0, time.UTC)

// Name is the org's name: the domain's label, capitalised.
func (o fakeOrgs) Name(_ context.Context, orgID uuid.UUID) (string, error) {
	for domain, id := range o {
		if id == orgID {
			label := strings.TrimSuffix(domain, ".com")
			return strings.ToUpper(label[:1]) + label[1:], nil
		}
	}
	return "", server.ErrNotFound
}

func (u *fakeUsers) MembershipByEmail(_ context.Context, orgID uuid.UUID, email string) (server.Membership, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	id, ok := u.users[email]
	if !ok {
		return server.Membership{}, server.ErrNotFound
	}
	for _, m := range u.memberships {
		if m.User.ID == id && m.OrgID == orgID {
			return m, nil
		}
	}
	return server.Membership{}, server.ErrNotFound
}

// CreateMembership is an invite being accepted: the user on first sight,
// the membership if none, a left one brought back. An org in u.capped is
// at its plan's limit.
func (u *fakeUsers) CreateMembership(_ context.Context, in server.NewMembership) (server.Membership, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.capped[in.OrgID] && in.Kind != "guest" {
		return server.Membership{}, &server.Refusal{Status: 422, Code: "plan.limit_reached"}
	}
	id, ok := u.users[in.Email]
	if !ok {
		id = uuid.New()
		u.users[in.Email] = id
	}
	for i := range u.memberships {
		m := &u.memberships[i]
		if m.User.ID == id && m.OrgID == in.OrgID {
			if m.Status == "left" {
				m.Status, m.Role = "active", in.Role
			}
			return *m, nil
		}
	}
	m := server.Membership{ID: uuid.New(), OrgID: in.OrgID, Status: "active", Role: in.Role}
	m.User.ID = id
	u.memberships = append(u.memberships, m)
	u.created = append(u.created, in)
	return m, nil
}

// memoryKeys is a KeySource: one data key per org, wrapped by the test KMS.
type memoryKeys struct {
	wrapper *filekms.KMS
	mu      sync.Mutex
	keys    map[string]envelope.WrappedKey
}

func (m *memoryKeys) Current(ctx context.Context, orgID string) (envelope.WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[orgID]; ok {
		return k, nil
	}
	raw, err := envelope.NewDataKey()
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	wrapped, _, err := m.wrapper.Wrap(ctx, raw)
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	k := envelope.WrappedKey{OrgID: orgID, Version: 1, Wrapped: wrapped}
	m.keys[orgID] = k
	return k, nil
}

func (m *memoryKeys) Version(ctx context.Context, orgID string, _ uint32) (envelope.WrappedKey, error) {
	return m.Current(ctx, orgID)
}

// memoryMail is the notification service's outbox, kept in memory.
type memoryMail struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *memoryMail) Send(_ context.Context, msg email.Message) (email.Queued, error) {
	if err := msg.Validate(); err != nil {
		return email.Queued{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return email.Queued{ID: uuid.NewString(), State: "queued"}, nil
}

// memoryEvents is the live-session bus as the tests see it: every event
// kept, and passed on to a real bus when a test sets one.
type memoryEvents struct {
	mu     sync.Mutex
	events []livebus.Event
	bus    livebus.Publisher
}

func (m *memoryEvents) Publish(ctx context.Context, ev livebus.Event) error {
	m.mu.Lock()
	m.events = append(m.events, ev)
	bus := m.bus
	m.mu.Unlock()
	if bus != nil {
		return bus.Publish(ctx, ev)
	}
	return nil
}

type memoryRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memoryRecorder) Record(_ context.Context, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

type fixture struct {
	t        *testing.T
	h        http.Handler
	idp      *fakeIdP
	users    *fakeUsers
	orgs     fakeOrgs
	recorder *memoryRecorder
	events   *memoryEvents
	mail     *memoryMail
	pool     *pgxpool.Pool
	verifier *auth.Verifier
	sig      *signer.Signer
	grants   authz.Static
	apps     map[string]string
	srv      *server.Server
	public   string
	// logs is everything the service logged, for tests that no secret or
	// token is among it.
	logs *syncBuffer
}

// syncBuffer is a buffer the service may log to from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const identityURL = "http://identity.test"

// The cookies' names under the default product id.
var (
	sessionName = config.DefaultCookies.Session
	signInName  = config.DefaultCookies.SignIn
)

// The whole path against a real Postgres, a fake provider, an in-memory
// user service, and the same auth mounting as main.
func newAPI(t *testing.T) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("identity")

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
	cluster := db.SingleShard(pool)

	wrapper, err := filekms.Open(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Load(ctx, cluster, wrapper, "identity-test", "b2bapp")
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewStaticVerifier("identity-test", "b2bapp", sig.PublicKeys())

	idp := newFakeIdP(t)
	oidcClient, err := oidc.New(ctx, idp.srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	users := newFakeUsers()
	orgs := fakeOrgs{"acme.com": acme, "globex.com": globex}
	recorder := &memoryRecorder{}
	events := &memoryEvents{}
	mail := &memoryMail{}
	// Failed sign-ins are counted in a real Redis, on its own database so
	// runs do not share buckets; without one the count is off (nil).
	var limiter *ratelimit.Limiter
	if url := os.Getenv("TEST_REDIS_URL"); url != "" {
		opts, err := redis.ParseURL(url)
		if err != nil {
			t.Fatal(err)
		}
		// Its own database, so flushing it wipes nobody else's buckets.
		opts.DB = 9
		rdb := redis.NewClient(opts)
		t.Cleanup(func() { rdb.Close() })
		if err := rdb.FlushDB(ctx).Err(); err != nil {
			t.Skipf("redis: %v", err)
		}
		limiter = ratelimit.New(rdb, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	grants := authz.Static{}
	apps := map[string]string{"account": "http://account.test", "admin": "http://admin.test", "platform": "http://platform.test"}
	logs := &syncBuffer{}
	var logOut io.Writer = logs
	if os.Getenv("TEST_LOG") != "" {
		logOut = io.MultiWriter(logs, os.Stderr)
	}
	logger := slog.New(slog.NewTextHandler(logOut, nil))
	srv := server.New(cluster, logger, recorder, sig, oidcClient, envelope.New(&memoryKeys{wrapper: wrapper, keys: map[string]envelope.WrappedKey{}}, wrapper),
		users, orgs, grants, events, mail, limiter, wrapper, server.Config{PublicURL: identityURL, Apps: apps, PlatformApp: "platform", AccessTTL: time.Minute, SecureCookies: false, EntraAuthority: idp.srv.URL, GoogleIssuer: idp.googleIssuer(), DesktopScheme: "b2bapp"})
	api := srv.Handler(httpx.NewMux())

	root := http.NewServeMux()
	httpx.Health(root)
	for _, p := range server.PublicPaths {
		root.Handle(p, api)
	}
	// A support session is audited as main wires it.
	verifier.WithImpersonationAudit(audit.Impersonation(recorder, "identity"))
	root.Handle("/", auth.Require(verifier, api))
	return &fixture{logs: logs, srv: srv, t: t, h: httpx.Logged(logger, root), idp: idp, users: users, orgs: orgs, recorder: recorder, events: events, mail: mail, pool: pool, verifier: verifier, sig: sig, grants: grants, apps: apps, public: identityURL}
}

// A browser: keeps cookies between requests.
type browser struct {
	f       *fixture
	cookies map[string]*http.Cookie
	// agent is its user agent; test-browser/1.0 when empty.
	agent string
}

func (f *fixture) browser() *browser { return &browser{f: f, cookies: map[string]*http.Cookie{}} }

func (b *browser) do(method, path, token string, body any) *httptest.ResponseRecorder {
	b.f.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, reader)
	agent := b.agent
	if agent == "" {
		agent = "test-browser/1.0"
	}
	req.Header.Set("User-Agent", agent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.f.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

func body(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON (%d): %q", rec.Code, rec.Body.String())
	}
	return out
}

// platform is a platform operator's token, signed by this issuer.
func (f *fixture) platform() string {
	raw, err := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: auth.PlatformOrg, MembershipID: uuid.NewString()}, time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// configure sets acme's identity provider to the fake, as an operator would.
func (f *fixture) configure(org uuid.UUID) {
	f.t.Helper()
	b := f.browser()
	rec := b.do(http.MethodPut, "/v1/organizations/"+org.String()+"/identity-provider", f.platform(),
		map[string]any{"preset": "entra", "tenant_id": "tenant", "client_id": f.idp.clientID, "client_secret": f.idp.secret})
	if rec.Code != http.StatusOK {
		f.t.Fatalf("configure provider: %d %s", rec.Code, rec.Body.String())
	}
}

// signIn walks the whole flow for one person and returns their browser and
// where the callback sent them.
func (f *fixture) signIn(b *browser, start string, who person) string {
	f.t.Helper()
	rec := b.do(http.MethodGet, start, "", nil)
	if rec.Code != http.StatusFound {
		f.t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	code, state := f.idp.authorize(f.t, rec.Header().Get("Location"), who)
	rec = b.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state="+state, "", nil)
	if rec.Code != http.StatusFound {
		f.t.Fatalf("callback: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

// FindByEmail is the person with an address.
func (u *fakeUsers) FindByEmail(_ context.Context, email string) (uuid.UUID, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if id, ok := u.users[email]; ok {
		return id, nil
	}
	return uuid.Nil, server.ErrNotFound
}

// SetEmail moves a person to another address, refused when it is taken.
func (u *fakeUsers) SetEmail(_ context.Context, userID uuid.UUID, email string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if other, ok := u.users[email]; ok && other != userID {
		return &server.Refusal{Status: 409, Code: "email.taken"}
	}
	for addr, id := range u.users {
		if id == userID {
			delete(u.users, addr)
		}
	}
	u.users[email] = userID
	return nil
}

// SignedIn remembers who signed in without a provider.
func (u *fakeUsers) SignedIn(_ context.Context, userID uuid.UUID) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.signedIn = append(u.signedIn, userID)
	return nil
}

// CountMembers is the org's active members.
func (u *fakeUsers) CountMembers(_ context.Context, orgID uuid.UUID) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, m := range u.memberships {
		if m.OrgID == orgID && m.Status == "active" {
			n++
		}
	}
	return n, nil
}

// emailOf is the address the user service has for a person.
func (u *fakeUsers) emailOf(userID uuid.UUID) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	for addr, id := range u.users {
		if id == userID {
			return addr
		}
	}
	return ""
}
