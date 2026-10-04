package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// API keys and personal access tokens.
//
// A script presents one as its bearer token, to the same middleware as a
// session's access token. The middleware asks the identity service what the
// key is, at that moment and every time: a revoked or expired key is refused
// on its next request. What it resolves to is a Key in the context, never a
// Caller: CallerFrom does not see it, so every check written for a person
// (RequireOrg, RequireService, RequirePlatform, a /me endpoint) refuses it,
// and a key reaches only what pkg/authz.Require admits it to, by the
// permission groups it was granted.

// The kinds of key.
const (
	// OrgKey is an org's API key: named, made by an admin, granted
	// permission groups, and acting as itself (actor api_key:<id>).
	OrgKey = "org"
	// PersonalKey is a person's personal access token: granted a subset of
	// their own groups, and acting as their membership. Each use is also
	// checked against what the person may do now.
	PersonalKey = "personal"
)

// Key is an API key or personal access token, as the identity service
// resolved it for this request. Ids only.
type Key struct {
	ID    string
	Kind  string
	OrgID string
	// UserID and MembershipID are the person a personal access token is
	// theirs; empty for an org's key.
	UserID       string
	MembershipID string
	// Groups is the permission groups it was granted.
	Groups []string
}

// Actor is the key as the author of a change: an org key itself, or the
// person whose token it is.
func (k Key) Actor() db.Actor {
	if k.Kind == PersonalKey {
		return db.MembershipActor(k.MembershipID)
	}
	return db.APIKeyActor(k.ID)
}

type keyKey struct{}

// WithKey is ctx carrying k, k's actor for any write, and its ids as the
// tags on any error report.
func WithKey(ctx context.Context, k Key) context.Context {
	ctx = errtrack.WithTags(ctx, map[string]string{"org_id": k.OrgID, "api_key_id": k.ID, "membership_id": k.MembershipID})
	return db.WithActor(context.WithValue(ctx, keyKey{}, k), k.Actor())
}

// KeyFrom is the key in ctx, if the request was made with one.
func KeyFrom(ctx context.Context) (Key, bool) {
	k, ok := ctx.Value(keyKey{}).(Key)
	return k, ok
}

// IsKeyToken reports whether a bearer token is an API key or a personal
// access token rather than an access token: an access token is a JWT,
// three parts joined by dots, and a key never has a dot.
func IsKeyToken(raw string) bool { return raw != "" && !strings.Contains(raw, ".") }

// KeyResolver says what a key is, now. The identity service answers from
// its table; another service asks it (KeyClient).
type KeyResolver interface {
	// Resolve is the key raw is, or ErrUnauthenticated when it is no key,
	// revoked or expired, or a *KeyRefusal when it is one that may not be
	// used right now (its rate limit, its org's plan).
	Resolve(ctx context.Context, raw string) (Key, error)
}

// KeyRefusal is a key that is real but refused for now, with the answer
// the client gets: 429 past its rate limit, 403 when the org's plan does
// not include API access.
type KeyRefusal struct {
	Status int
	Body   httpx.Error
	// RetryAfter is seconds, for a 429.
	RetryAfter int
}

func (r *KeyRefusal) Error() string {
	return fmt.Sprintf("auth: key refused: %d %s", r.Status, r.Body.Code)
}

// WithKeys is v accepting API keys and personal access tokens too, each
// resolved by r on every request. Without it, a key is refused like any
// token that does not verify.
func (v *Verifier) WithKeys(r KeyResolver) *Verifier {
	v.resolver = r
	return v
}

// resolve answers a request that brought a key: the next handler with the
// key in the context, or the refusal.
func (v *Verifier) resolve(w http.ResponseWriter, r *http.Request, raw string, next http.Handler) {
	if v.resolver == nil {
		unauthenticated(w)
		return
	}
	k, err := v.resolver.Resolve(r.Context(), raw)
	var refusal *KeyRefusal
	switch {
	case err == nil:
		next.ServeHTTP(w, r.WithContext(WithKey(r.Context(), k)))
	case errors.As(err, &refusal):
		if refusal.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(refusal.RetryAfter))
		}
		httpx.WriteJSON(w, refusal.Status, refusal.Body)
	case errors.Is(err, ErrUnauthenticated):
		unauthenticated(w)
	default:
		errtrack.Capture(r.Context(), err)
		httpx.WriteError(w, http.StatusServiceUnavailable, httpx.CodeUnavailable, "Try again in a moment.")
	}
}

// keyClient asks the identity service what a key is, as this service, on
// every request. Nothing is cached: a revocation is seen on the next one.
type keyClient struct {
	base   string
	tokens TokenSource
	http   *http.Client
}

// KeyClient is a KeyResolver over the identity service at baseURL.
func KeyClient(baseURL string, tokens TokenSource, h *http.Client) KeyResolver {
	if h == nil {
		h = &http.Client{Timeout: 5 * time.Second}
	}
	return &keyClient{base: strings.TrimSuffix(baseURL, "/"), tokens: tokens, http: h}
}

// KeyWire is a resolved key as the identity service's internal endpoint
// answers it.
type KeyWire struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	OrgID        string   `json:"org_id"`
	UserID       string   `json:"user_id,omitempty"`
	MembershipID string   `json:"membership_id,omitempty"`
	Groups       []string `json:"groups"`
}

func (c *keyClient) Resolve(ctx context.Context, raw string) (Key, error) {
	body, _ := json.Marshal(map[string]string{"token": raw})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/internal/api-keys/resolve", bytes.NewReader(body))
	if err != nil {
		return Key{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := Authorize(ctx, c.tokens, req); err != nil {
		return Key{}, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Key{}, fmt.Errorf("auth: resolve key: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var k KeyWire
		if err := json.NewDecoder(resp.Body).Decode(&k); err != nil {
			return Key{}, fmt.Errorf("auth: resolve key: %w", err)
		}
		return Key(k), nil
	case http.StatusUnauthorized:
		return Key{}, ErrUnauthenticated
	case http.StatusForbidden, http.StatusTooManyRequests:
		var e httpx.Error
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&e); err != nil {
			return Key{}, fmt.Errorf("auth: resolve key: %w", err)
		}
		retry, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return Key{}, &KeyRefusal{Status: resp.StatusCode, Body: e, RetryAfter: retry}
	default:
		return Key{}, fmt.Errorf("auth: identity service answered %d resolving a key", resp.StatusCode)
	}
}
