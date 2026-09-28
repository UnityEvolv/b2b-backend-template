// Package oidc is the OpenID Connect authorization code flow with PKCE, as a
// relying party: discover the provider, send the browser to it, exchange the
// code, validate the identity token. Entra is the first provider; nothing
// here is Entra-specific beyond the issuer's shape.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Provider is what discovery says about an issuer.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Client talks to identity providers. One per process; it caches discovery
// documents and key sets per issuer.
type Client struct {
	http *http.Client

	mu        sync.Mutex
	providers map[string]Provider
	keys      *jwk.Cache
}

// New is a client. h is for tests; nil is a sensible default.
func New(ctx context.Context, h *http.Client) (*Client, error) {
	if h == nil {
		h = &http.Client{Timeout: 10 * time.Second}
	}
	cache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithHTTPClient(h)))
	if err != nil {
		return nil, err
	}
	return &Client{http: h, providers: map[string]Provider{}, keys: cache}, nil
}

// EntraAuthority is where Entra tenants live. A test points it elsewhere.
const EntraAuthority = "https://login.microsoftonline.com"

// EntraIssuer is the v2 issuer for an Entra tenant under authority. The
// tenant may be a GUID or a verified domain.
func EntraIssuer(authority, tenant string) string {
	return strings.TrimSuffix(authority, "/") + "/" + url.PathEscape(strings.TrimSpace(tenant)) + "/v2.0"
}

// Discover fetches the issuer's configuration: the real round trip that
// proves the settings before they are saved.
func (c *Client) Discover(ctx context.Context, issuer string) (Provider, error) {
	c.mu.Lock()
	if p, ok := c.providers[issuer]; ok {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return Provider{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Provider{}, fmt.Errorf("oidc: discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Provider{}, fmt.Errorf("oidc: discover: status %d", resp.StatusCode)
	}
	var p Provider
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return Provider{}, fmt.Errorf("oidc: discover: %w", err)
	}
	if p.Issuer == "" || p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return Provider{}, errors.New("oidc: discover: incomplete configuration")
	}
	// Entra publishes its issuer with the tenant id even when asked by
	// domain, so the document's issuer is the one tokens carry.
	c.mu.Lock()
	c.providers[issuer] = p
	c.mu.Unlock()
	if err := c.keys.Register(ctx, p.JWKSURI, jwk.WithMinInterval(time.Minute)); err != nil {
		return Provider{}, fmt.Errorf("oidc: keys: %w", err)
	}
	return p, nil
}

// PKCE is a code verifier and its challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE is a fresh verifier and its S256 challenge.
func NewPKCE() (PKCE, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PKCE{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// Nonce is a fresh random value.
func Nonce() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthorizeURL is where to send the browser.
func AuthorizeURL(p Provider, clientID, redirectURI, state, nonce string, pkce PKCE) string {
	q := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.AuthorizationEndpoint + sep + q.Encode()
}

// Claims is what the identity token said about the person.
type Claims struct {
	Subject string
	Email   string
	Name    string
	// Directory attributes the provider chose to include. Entra sends these
	// as optional claims when the app registration asks for them.
	JobTitle, Department, EmployeeType, Country, City string
}

// ErrRefused means the provider or the token said no: a wrong code, a token
// for another audience, a nonce that does not match. Never retried.
var ErrRefused = errors.New("oidc: refused")

// Exchange trades the code for tokens and validates the identity token.
func (c *Client) Exchange(ctx context.Context, p Provider, clientID, clientSecret, redirectURI, code, verifier, nonce string) (Claims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Claims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: token: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Claims{}, fmt.Errorf("oidc: token: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.IDToken == "" {
		if body.Error != "" {
			return Claims{}, fmt.Errorf("%w: %s", ErrRefused, body.Error)
		}
		return Claims{}, fmt.Errorf("oidc: token: status %d", resp.StatusCode)
	}
	return c.validate(ctx, p, clientID, body.IDToken, nonce)
}

func (c *Client) validate(ctx context.Context, p Provider, clientID, raw, nonce string) (Claims, error) {
	set, err := c.keys.Lookup(ctx, p.JWKSURI)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: keys: %w", err)
	}
	token, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(clientID),
		jwt.WithAcceptableSkew(2*time.Minute),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("exp"),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: identity token: %v", ErrRefused, err)
	}
	var got string
	if err := token.Get("nonce", &got); err != nil || got != nonce {
		return Claims{}, fmt.Errorf("%w: nonce", ErrRefused)
	}
	var claims Claims
	claims.Subject, _ = token.Subject()
	str := func(name string) string {
		var v string
		_ = token.Get(name, &v)
		return v
	}
	// Entra puts the address in preferred_username when email is absent.
	claims.Email = str("email")
	if claims.Email == "" {
		claims.Email = str("preferred_username")
	}
	claims.Name = str("name")
	claims.JobTitle, claims.Department = str("jobTitle"), str("department")
	claims.EmployeeType, claims.Country, claims.City = str("employeeType"), str("country"), str("city")
	if claims.Subject == "" || claims.Email == "" {
		return Claims{}, fmt.Errorf("%w: no subject or email", ErrRefused)
	}
	return claims, nil
}
