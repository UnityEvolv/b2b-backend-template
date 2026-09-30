package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

const (
	issuerName = "b2bapp-test"
	audience   = "b2bapp"
	user       = "01922b5e-0000-7000-8000-0000000000d1"
	org        = "01922b5e-0000-7000-8000-0000000000d2"
	member     = "01922b5e-0000-7000-8000-0000000000d3"
)

func issuer(t *testing.T, name string) *stubissuer.Issuer {
	t.Helper()
	i, err := stubissuer.New(name, audience)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func token(t *testing.T, i *stubissuer.Issuer, c auth.Caller) string {
	t.Helper()
	raw, err := i.Issue(c, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// echo answers with the caller the middleware put in the context.
var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	c, _ := auth.CallerFrom(r.Context())
	actor, _ := db.ActorFrom(r.Context())
	_ = json.NewEncoder(w).Encode(map[string]string{"user": c.UserID, "org": c.OrgID, "actor": string(actor)})
})

func call(h http.Handler, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestValidTokenPutsTheCallerInContext(t *testing.T) {
	i := issuer(t, issuerName)
	h := auth.Require(auth.NewStaticVerifier(issuerName, audience, i.PublicKeys()), echo)

	rec := call(h, "Bearer "+token(t, i, auth.Caller{UserID: user, OrgID: org, MembershipID: member}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["user"] != user || got["org"] != org || got["actor"] != "membership:"+member {
		t.Fatalf("context: %v", got)
	}

	// A token not scoped to an org acts as the user.
	rec = call(h, "Bearer "+token(t, i, auth.Caller{UserID: user}))
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["actor"] != "user:"+user || got["org"] != "" {
		t.Fatalf("user token: %d %v", rec.Code, got)
	}
}

func TestEveryBadTokenIsRefusedTheSameWay(t *testing.T) {
	i := issuer(t, issuerName)
	stranger := issuer(t, issuerName) // same name, different key
	otherIssuer := issuer(t, "someone-else")
	verifier := auth.NewStaticVerifier(issuerName, audience, i.PublicKeys())
	h := auth.Require(verifier, echo)

	valid := auth.Caller{UserID: user, OrgID: org, MembershipID: member}
	expired, err := i.IssueAt(valid, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good := token(t, i, valid)
	parts := strings.Split(good, ".")
	unsigned := parts[0] + "." + parts[1] + "."
	tampered := parts[0] + "." + strings.TrimRight(parts[1], "=") + "x." + parts[2]

	cases := map[string]string{
		"no header":            "",
		"not bearer":           "Basic " + good,
		"empty bearer":         "Bearer ",
		"garbage":              "Bearer not.a.token",
		"signed by a stranger": "Bearer " + token(t, stranger, valid),
		"wrong issuer":         "Bearer " + token(t, otherIssuer, valid),
		"expired":              "Bearer " + expired,
		"unsigned":             "Bearer " + unsigned,
		"tampered payload":     "Bearer " + tampered,
		"sub not a user id":    "Bearer " + token(t, i, auth.Caller{UserID: "admin"}),
		"org without member":   "Bearer " + token(t, i, auth.Caller{UserID: user, OrgID: org}),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			rec := call(h, header)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
			var body map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body["code"] != "unauthenticated" || body["message"] != "Sign in to continue." {
				t.Fatalf("body %v: every failure must look the same", body)
			}
			if rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("no WWW-Authenticate")
			}
		})
	}
}

func TestWrongAudienceIsRefused(t *testing.T) {
	i, err := stubissuer.New(issuerName, "another-product")
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewStaticVerifier(issuerName, audience, i.PublicKeys())
	if _, err := verifier.Verify(token(t, i, auth.Caller{UserID: user})); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("got %v", err)
	}
}

func TestRequireOrg(t *testing.T) {
	ctx := auth.WithCaller(context.Background(), auth.Caller{UserID: user, OrgID: org, MembershipID: member})
	if err := auth.RequireOrg(ctx, org); err != nil {
		t.Fatalf("own org: %v", err)
	}
	if err := auth.RequireOrg(ctx, strings.ToUpper(org)); err != nil {
		t.Fatalf("own org, other case: %v", err)
	}
	if err := auth.RequireOrg(ctx, "01922b5e-0000-7000-8000-0000000000ff"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("other org: %v", err)
	}
	userOnly := auth.WithCaller(context.Background(), auth.Caller{UserID: user})
	if err := auth.RequireOrg(userOnly, org); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("token without an org: %v", err)
	}
	if err := auth.RequireOrg(context.Background(), org); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("no caller: %v", err)
	}
}

// The verifier fetches keys from the issuer's JWKS URL, the way services run.
func TestVerifierFetchesKeysFromTheIssuer(t *testing.T) {
	i := issuer(t, issuerName)
	srv := httptest.NewServer(i.Handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifier, err := auth.NewVerifier(ctx, issuerName, audience, srv.URL+"/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(srv.URL+"/token", "application/json", strings.NewReader(`{"user_id":"`+user+`","org_id":"`+org+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var issued struct {
		AccessToken  string `json:"access_token"`
		MembershipID string `json:"membership_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	c, err := verifier.Verify(issued.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.UserID != user || c.OrgID != org || c.MembershipID != issued.MembershipID || c.SessionID == "" {
		t.Fatalf("caller %+v", c)
	}
}

func TestServiceTokens(t *testing.T) {
	i := issuer(t, issuerName)
	verifier := auth.NewStaticVerifier(issuerName, audience, i.PublicKeys())

	c, err := verifier.Verify(token(t, i, auth.Caller{Service: "organization"}))
	if err != nil || c.Service != "organization" || !c.IsService() || c.UserID != "" {
		t.Fatalf("service token: %+v %v", c, err)
	}
	if c.Actor() != db.SystemActor("organization") {
		t.Fatalf("actor %q", c.Actor())
	}

	// A name not registered in pkg/db is not a service.
	if _, err := verifier.Verify(token(t, i, auth.Caller{Service: "not-a-service"})); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("unknown service accepted: %v", err)
	}
	// A service token never carries a person or an org.
	if _, err := verifier.Verify(token(t, i, auth.Caller{Service: "organization", OrgID: org, MembershipID: member})); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("service token with an org accepted: %v", err)
	}

	// The middleware marks the call internal, so limits for people skip it.
	var internal bool
	h := auth.Require(verifier, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		internal = httpx.IsInternalCall(r.Context())
	}))
	call(h, "Bearer "+token(t, i, auth.Caller{Service: "organization"}))
	if !internal {
		t.Fatal("a service call was not marked internal")
	}
	call(h, "Bearer "+token(t, i, auth.Caller{UserID: user}))
	if internal {
		t.Fatal("a person's call was marked internal")
	}
}

func TestRequireService(t *testing.T) {
	svc := auth.WithCaller(context.Background(), auth.Caller{Service: "organization"})
	person := auth.WithCaller(context.Background(), auth.Caller{UserID: user, OrgID: org, MembershipID: member})

	if err := auth.RequireService(svc); err != nil {
		t.Fatalf("any service: %v", err)
	}
	if err := auth.RequireService(svc, "organization", "identity"); err != nil {
		t.Fatalf("named service: %v", err)
	}
	if err := auth.RequireService(svc, "identity"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("other service: %v", err)
	}
	if err := auth.RequireService(person); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("a person on an internal endpoint: %v", err)
	}
	if err := auth.RequireService(context.Background()); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("no caller: %v", err)
	}
}

func TestStubIssuerMintsServiceTokens(t *testing.T) {
	i := issuer(t, issuerName)
	srv := httptest.NewServer(i.Handler())
	defer srv.Close()
	verifier := auth.NewStaticVerifier(issuerName, audience, i.PublicKeys())

	source := auth.IssuerTokenSource(srv.URL, "organization", srv.Client())
	raw, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := verifier.Verify(raw)
	if err != nil || c.Service != "organization" {
		t.Fatalf("%+v %v", c, err)
	}
	// Cached until it nears expiry: the same token comes back.
	again, _ := source.Token(context.Background())
	if again != raw {
		t.Fatal("token was not cached")
	}

	resp, err := http.Post(srv.URL+"/token", "application/json", strings.NewReader(`{"service":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown service: %d", resp.StatusCode)
	}
}

// A product's service owns no schema in
// this process, so the template's services know it only from the
// data-owner registry, which they read from DATA_OWNERS. Once it is there,
// its tokens are accepted.
func TestAProductServiceIsKnownFromTheDataOwnerRegistry(t *testing.T) {
	i := issuer(t, issuerName)
	verifier := auth.NewStaticVerifier(issuerName, audience, i.PublicKeys())
	product := token(t, i, auth.Caller{Service: "projects"})
	if _, err := verifier.Verify(product); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("an unregistered product service accepted: %v", err)
	}
	if err := dataowner.Default.Load(`[{"name":"projects","export":true,"purge":true,"erase":true}]`); err != nil {
		t.Fatal(err)
	}
	if c, err := verifier.Verify(product); err != nil || c.Service != "projects" {
		t.Fatalf("a registered product service: %+v %v", c, err)
	}
	if !auth.KnownService("projects") || auth.KnownService("documents") {
		t.Error("KnownService does not follow the registry")
	}
}
