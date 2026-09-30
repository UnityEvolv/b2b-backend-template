package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// The checks a provider's settings pass before they are saved, in order.
const (
	CheckDiscovery = "discovery"
	CheckIssuer    = "issuer"
	CheckKeys      = "keys"
	CheckClient    = "client"
)

// Check is one step of the test: whether it passed, and when it did not,
// which input to fix. Message is for the admin; it never carries a secret.
type Check struct {
	Name    string
	OK      bool
	Field   string
	Message string
}

// Tested is the outcome of Test.
type Tested struct {
	// Provider is the discovery document, once it was fetched.
	Provider Provider
	Checks   []Check
}

// OK is whether every check passed.
func (t Tested) OK() bool {
	for _, c := range t.Checks {
		if !c.OK {
			return false
		}
	}
	return len(t.Checks) > 0
}

// Test is the round trip a provider's settings pass before they are saved,
// without a person signing in:
//
//  1. discovery: the issuer's discovery document is fetched, fresh.
//  2. issuer: it names the issuer asked for (loose: the same host, for
//     Entra asked by domain).
//  3. keys: its key set loads and has a signing key.
//  4. client: the token endpoint is sent an authorization code that cannot
//     exist, with the client's credentials. A provider checks the client
//     before the code (RFC 6749 section 5.2): invalid_client means the id
//     or secret is wrong, invalid_grant means they are right.
//
// A check after a failed one is not run. field is the input the issuer came
// from (issuer, or tenant_id for Entra). On success the provider's keys are
// registered for sign-in.
func (c *Client) Test(ctx context.Context, s Settings, redirectURI string, loose bool, field string) Tested {
	var out Tested
	fail := func(name, field, format string, args ...any) Tested {
		out.Checks = append(out.Checks, Check{Name: name, Field: field, Message: fmt.Sprintf(format, args...)})
		return out
	}
	pass := func(name, format string, args ...any) {
		out.Checks = append(out.Checks, Check{Name: name, OK: true, Message: fmt.Sprintf(format, args...)})
	}

	p, err := c.fetch(ctx, s.Issuer)
	if err != nil {
		return fail(CheckDiscovery, field, "The discovery document at %s could not be read (%s).", discoveryURL(s.Issuer), strings.TrimPrefix(err.Error(), "oidc: discover: "))
	}
	out.Provider = p
	pass(CheckDiscovery, "The discovery document at %s was read.", discoveryURL(s.Issuer))

	if !issuerMatches(s.Issuer, p.Issuer, loose) {
		return fail(CheckIssuer, field, "The discovery document names the issuer %s, not %s.", p.Issuer, s.Issuer)
	}
	pass(CheckIssuer, "The issuer is %s.", p.Issuer)

	set, err := jwk.Fetch(ctx, p.JWKSURI, jwk.WithHTTPClient(c.http))
	if err != nil {
		return fail(CheckKeys, field, "The provider's signing keys at %s could not be read.", p.JWKSURI)
	}
	n := 0
	for i := range set.Len() {
		key, _ := set.Key(i)
		if use, ok := key.KeyUsage(); !ok || use == "sig" {
			n++
		}
	}
	if n == 0 {
		return fail(CheckKeys, field, "The provider publishes no signing key at %s.", p.JWKSURI)
	}
	pass(CheckKeys, "The provider publishes %d signing key(s).", n)

	if msg, field, ok := c.probe(ctx, p, s, redirectURI); !ok {
		return fail(CheckClient, field, "%s", msg)
	} else {
		pass(CheckClient, "%s", msg)
	}

	if err := c.register(ctx, p); err != nil {
		return fail(CheckKeys, field, "The provider's signing keys could not be loaded for sign-in.")
	}
	return out
}

// issuerMatches is whether the document's issuer is the one asked for.
func issuerMatches(asked, got string, loose bool) bool {
	if got == asked {
		return true
	}
	if !loose {
		return false
	}
	a, err1 := url.Parse(asked)
	g, err2 := url.Parse(got)
	return err1 == nil && err2 == nil && a.Scheme == g.Scheme && strings.EqualFold(a.Host, g.Host)
}

// probe presents the client's credentials with a code that cannot exist.
func (c *Client) probe(ctx context.Context, p Provider, s Settings, redirectURI string) (message, field string, ok bool) {
	code, err := Nonce()
	if err != nil {
		return "The test could not be run.", "", false
	}
	verifier, err := NewPKCE()
	if err != nil {
		return "The test could not be run.", "", false
	}
	status, body, err := c.post(ctx, p, s.ClientID, s.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"test-" + code},
		"redirect_uri":  {redirectURI},
		"client_id":     {s.ClientID},
		"code_verifier": {verifier.Verifier},
	})
	if err != nil {
		return "The provider's token endpoint could not be reached.", "", false
	}
	switch ErrorCode(body.Error) {
	case "invalid_grant":
		return "The provider accepted the client id and secret.", "", true
	case "invalid_client":
		return "The provider refused the client id and secret.", "client_secret", false
	case "unauthorized_client":
		return "The provider does not let this client id sign people in with an authorization code.", "client_id", false
	case "":
		if status == http.StatusOK {
			return "The provider's token endpoint accepted a code that cannot exist.", "", false
		}
		if status == http.StatusUnauthorized {
			return "The provider refused the client id and secret.", "client_secret", false
		}
		return fmt.Sprintf("The provider's token endpoint answered status %d.", status), "", false
	default:
		return fmt.Sprintf("The provider's token endpoint answered %s rather than accepting or refusing the client.", ErrorCode(body.Error)), "", false
	}
}
