package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

const keyID = "01922b5e-0000-7000-8000-0000000000e1"

// fakeIdentity is the identity service's resolve endpoint over a map of
// tokens, counting the calls.
func fakeIdentity(t *testing.T, keys map[string]auth.KeyWire) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/internal/api-keys/resolve" || r.Header.Get("Authorization") != "Bearer service-token" {
			httpx.WriteError(w, http.StatusForbidden, httpx.CodeForbidden, "Services only.")
			return
		}
		var in struct{ Token string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Token {
		case "b2bapp_ak_busy":
			w.Header().Set("Retry-After", "7")
			httpx.WriteError(w, http.StatusTooManyRequests, httpx.CodeRateLimited, "Too many requests with this key.")
			return
		case "b2bapp_ak_free":
			httpx.WriteJSON(w, http.StatusForbidden, httpx.Error{Code: "plan.limit_reached", Message: "The free plan does not include API access.", Fields: map[string]string{"limit": "api_access"}})
			return
		}
		k, ok := keys[in.Token]
		if !ok {
			httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthenticated, "Sign in to continue.")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, k)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// A key is resolved by the identity service on every request, never
// cached, and lands in the context as a Key, never a Caller: every check
// written for a person or a service refuses it, and its actor is the key.
func TestKeysAreResolvedOnEveryRequest(t *testing.T) {
	identity, calls := fakeIdentity(t, map[string]auth.KeyWire{
		"b2bapp_ak_good": {ID: keyID, Kind: auth.OrgKey, OrgID: org, Groups: []string{"users"}},
	})
	var seen auth.Key
	var orgErr, svcErr, platformErr error
	var hasCaller bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = auth.KeyFrom(r.Context())
		_, hasCaller = auth.CallerFrom(r.Context())
		orgErr = auth.RequireOrg(r.Context(), org)
		svcErr = auth.RequireService(r.Context())
		platformErr = auth.RequirePlatform(r.Context())
		actor, _ := db.ActorFrom(r.Context())
		_, _ = w.Write([]byte(actor))
	})
	v := auth.NewStaticVerifier(issuerName, audience, issuer(t, issuerName).PublicKeys())
	h := auth.Require(v, inner)

	// Without a resolver, a key is a token that does not verify.
	if rec := call(h, "Bearer b2bapp_ak_good"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no resolver: %d", rec.Code)
	}
	v.WithKeys(auth.KeyClient(identity.URL, auth.StaticToken("service-token"), nil))
	for n := 1; n <= 2; n++ {
		rec := call(h, "Bearer b2bapp_ak_good")
		if rec.Code != http.StatusOK || rec.Body.String() != "api_key:"+keyID || *calls != n {
			t.Fatalf("request %d: %d %q, %d calls", n, rec.Code, rec.Body.String(), *calls)
		}
	}
	if seen.ID != keyID || seen.OrgID != org || len(seen.Groups) != 1 || hasCaller {
		t.Errorf("in the context: %+v, caller %v", seen, hasCaller)
	}
	for name, err := range map[string]error{"org": orgErr, "service": svcErr, "platform": platformErr} {
		if !errors.Is(err, auth.ErrForbidden) {
			t.Errorf("%s check let a key through: %v", name, err)
		}
	}

	if rec := call(h, "Bearer b2bapp_ak_gone"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown: %d", rec.Code)
	}
	if rec := call(h, "Bearer b2bapp_ak_busy"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "7" {
		t.Errorf("rate limited: %d %v", rec.Code, rec.Header())
	}
	rec := call(h, "Bearer b2bapp_ak_free")
	var body httpx.Error
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if rec.Code != http.StatusForbidden || body.Code != "plan.limit_reached" || body.Fields["limit"] != "api_access" {
		t.Errorf("plan: %d %+v", rec.Code, body)
	}
	// The identity service down is not a sign-in failure.
	identity.Close()
	if rec := call(h, "Bearer b2bapp_ak_good"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("identity down: %d", rec.Code)
	}
}

// A personal access token acts as its person's membership.
func TestPersonalTokenActsAsItsPerson(t *testing.T) {
	k := auth.Key{ID: keyID, Kind: auth.PersonalKey, OrgID: org, UserID: user, MembershipID: member}
	actor, _ := db.ActorFrom(auth.WithKey(context.Background(), k))
	if actor != db.MembershipActor(member) {
		t.Errorf("actor: %q", actor)
	}
	if auth.IsKeyToken("a.b.c") || !auth.IsKeyToken("b2bapp_pat_x") || auth.IsKeyToken("") {
		t.Error("a JWT is told from a key by its dots")
	}
}
