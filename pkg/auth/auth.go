// Package auth checks who is calling (UO-41).
//
// Every request to a service API carries a bearer token. The middleware
// verifies it against the issuer's published keys and puts the caller in the
// request context: who they are, which org the token is for, and which
// membership. Anything without a valid token is refused before a handler runs.
//
// The issuer is the identity service once sign-in lands (UO-51). Until then a
// stub issuer (cmd/stubissuer) mints tokens for local development; services do
// not know the difference, because they only ever see the keys and the issuer
// name they are configured with.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Private claims. Short, because they travel on every request.
const (
	ClaimOrg        = "org" // org_id the token is scoped to
	ClaimMembership = "mbr" // membership id in that org
	ClaimSession    = "sid" // session, for revocation (UO-77)
	ClaimService    = "svc" // a service calling another service, by name
)

// Caller is who is making the request. Ids only: never a name or an email.
//
// Either a person (UserID, and OrgID/MembershipID when acting in an org) or
// a service calling another service (Service), never both.
type Caller struct {
	UserID       string
	OrgID        string // empty for a token not scoped to an org
	MembershipID string // empty when OrgID is
	SessionID    string
	// Service is the calling service's name from pkg/db.Services, for an
	// internal call. Such a caller is in no org and is not rate limited.
	Service string
}

// IsService reports whether the caller is another service, not a person.
func (c Caller) IsService() bool { return c.Service != "" }

// Actor is the caller as the author of a change: the membership when acting
// in an org, the user otherwise.
func (c Caller) Actor() db.Actor {
	if c.Service != "" {
		return db.SystemActor(c.Service)
	}
	if c.MembershipID != "" {
		return db.MembershipActor(c.MembershipID)
	}
	return db.UserActor(c.UserID)
}

type callerKey struct{}

// WithCaller is ctx carrying c, c as the actor for any write, and c's ids as
// the tags on any error report.
func WithCaller(ctx context.Context, c Caller) context.Context {
	ctx = errtrack.WithTags(ctx, map[string]string{
		"user_id": c.UserID, "org_id": c.OrgID, "membership_id": c.MembershipID, "caller_service": c.Service,
	})
	return db.WithActor(context.WithValue(ctx, callerKey{}, c), c.Actor())
}

// CallerFrom is the caller in ctx, if the request was authenticated.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// ErrUnauthenticated means there is no valid token.
var ErrUnauthenticated = errors.New("auth: no valid token")

// ErrForbidden means the caller is authenticated but not for this org.
var ErrForbidden = errors.New("auth: not permitted for this org")

// RequireOrg is nil when the caller's token is for orgID.
//
// This is the tenant boundary, not the permission model: whether a member may
// do a particular thing in their org is UO-53's role check, layered on top.
func RequireOrg(ctx context.Context, orgID string) error {
	c, ok := CallerFrom(ctx)
	if !ok {
		return ErrUnauthenticated
	}
	if c.OrgID == "" || !strings.EqualFold(c.OrgID, orgID) {
		return ErrForbidden
	}
	return nil
}

// RequireService is nil when the caller is one of the named services (any
// service when none are named). A person's token is refused: internal
// endpoints are for services only.
func RequireService(ctx context.Context, names ...string) error {
	c, ok := CallerFrom(ctx)
	if !ok {
		return ErrUnauthenticated
	}
	if !c.IsService() || (len(names) > 0 && !slices.Contains(names, c.Service)) {
		return ErrForbidden
	}
	return nil
}

// Verifier checks tokens from one issuer, for one audience.
type Verifier struct {
	issuer   string
	audience string
	keys     jwk.Set
	ready    func(context.Context) error
}

// Skew tolerated between the issuer's clock and ours.
const skew = 30 * time.Second

// NewVerifier fetches the issuer's keys from jwksURL and keeps them fresh, so
// a rotated key is picked up without a restart.
//
// It returns without waiting for the first fetch, so a service can start before
// its issuer does; Ready reports whether keys have arrived, for /readyz.
func NewVerifier(ctx context.Context, issuer, audience, jwksURL string) (*Verifier, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, err
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(time.Minute), jwk.WithWaitReady(false)); err != nil {
		return nil, fmt.Errorf("auth: keys from %s: %w", jwksURL, err)
	}
	keys, err := cache.CachedSet(jwksURL)
	if err != nil {
		return nil, err
	}
	ready := func(ctx context.Context) error {
		if !cache.Ready(ctx, jwksURL) {
			return errors.New("auth: no keys from the issuer yet")
		}
		return nil
	}
	return &Verifier{issuer: issuer, audience: audience, keys: keys, ready: ready}, nil
}

// NewStaticVerifier checks tokens against a fixed key set. For tests.
func NewStaticVerifier(issuer, audience string, keys jwk.Set) *Verifier {
	return &Verifier{issuer: issuer, audience: audience, keys: keys, ready: func(context.Context) error { return nil }}
}

// Ready is nil once the issuer's keys have been fetched.
func (v *Verifier) Ready(ctx context.Context) error { return v.ready(ctx) }

// Verify is the caller a raw token speaks for, or ErrUnauthenticated.
func (v *Verifier) Verify(raw string) (Caller, error) {
	token, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(v.keys),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithAcceptableSkew(skew),
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("sub"),
	)
	if err != nil {
		return Caller{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	var c Caller
	_ = token.Get(ClaimService, &c.Service)
	if c.Service != "" {
		// A service token names the service as its subject and carries no
		// person, org or session.
		sub, _ := token.Subject()
		if !KnownService(c.Service) || sub != "service:"+c.Service {
			return Caller{}, fmt.Errorf("%w: unknown service", ErrUnauthenticated)
		}
		for _, claim := range []string{ClaimOrg, ClaimMembership, ClaimSession} {
			if token.Has(claim) {
				return Caller{}, fmt.Errorf("%w: a service token carries no %s", ErrUnauthenticated, claim)
			}
		}
		return c, nil
	}
	c.UserID, _ = token.Subject()
	_ = token.Get(ClaimOrg, &c.OrgID)
	_ = token.Get(ClaimMembership, &c.MembershipID)
	_ = token.Get(ClaimSession, &c.SessionID)

	if uuid.Validate(c.UserID) != nil {
		return Caller{}, fmt.Errorf("%w: sub is not a user id", ErrUnauthenticated)
	}
	if (c.OrgID == "") != (c.MembershipID == "") {
		return Caller{}, fmt.Errorf("%w: org and membership come together", ErrUnauthenticated)
	}
	for _, id := range []string{c.OrgID, c.MembershipID} {
		if id != "" && uuid.Validate(id) != nil {
			return Caller{}, fmt.Errorf("%w: malformed id claim", ErrUnauthenticated)
		}
	}
	return c, nil
}

// Require refuses any request without a valid bearer token, and puts the
// caller in the context of every one it lets through.
func Require(v *Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			unauthenticated(w)
			return
		}
		caller, err := v.Verify(raw)
		if err != nil {
			unauthenticated(w)
			return
		}
		ctx := WithCaller(r.Context(), caller)
		if caller.IsService() {
			// Internal calls are not rate limited; the token is what admits them.
			ctx = httpx.WithInternalCall(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Optional is Require for routes that also admit someone with no account,
// on a credential the handler checks itself (a join link visitor's key for
// their own call leg): a bearer token, when sent, must be valid and puts the
// caller in the context; with none, the request goes through with no caller,
// and the handler refuses anything it cannot prove.
func Optional(v *Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			next.ServeHTTP(w, r)
			return
		}
		Require(v, next).ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}

// unauthenticated says the same thing for every failure: which check failed is
// for our logs, never for whoever sent the token.
func unauthenticated(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer`)
	httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthenticated, "Sign in to continue.")
}

// PlatformOrg is the org id of the platform itself: the tenant that owns no
// office and whose members run the platform. A token for it is a platform
// operator's. It routes to shard 0 and is never a customer.
const PlatformOrg = "00000000-0000-7000-8000-000000000000"

// RequirePlatform is nil when the caller is a person signed in to the
// platform org: a platform operator. A service token is refused; a service
// acting platform-wide uses RequireService. Which operators may do what is
// the platform role check, layered on top.
func RequirePlatform(ctx context.Context) error {
	c, ok := CallerFrom(ctx)
	if !ok {
		return ErrUnauthenticated
	}
	if c.IsService() || !strings.EqualFold(c.OrgID, PlatformOrg) {
		return ErrForbidden
	}
	return nil
}

// RequireOrgOrPlatform is nil when the caller is in orgID or is a platform
// operator: an org's own settings are also visible to the people who run
// the platform.
func RequireOrgOrPlatform(ctx context.Context, orgID string) error {
	if err := RequireOrg(ctx, orgID); err == nil || errors.Is(err, ErrUnauthenticated) {
		return err
	}
	return RequirePlatform(ctx)
}

// serviceOnly are the services that call others but own no database schema,
// so they are not in pkg/db.Services: a product's own service written in
// another language, say. The template has none.
var serviceOnly = []string{}

// KnownService reports whether name is a service of the platform, and so may
// hold a service token.
func KnownService(name string) bool {
	if _, ok := db.ServiceByName(name); ok {
		return true
	}
	return slices.Contains(serviceOnly, name)
}
