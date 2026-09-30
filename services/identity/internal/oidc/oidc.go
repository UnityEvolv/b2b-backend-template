// Package oidc is the OpenID Connect authorization code flow with PKCE, as a
// relying party: discover the provider, send the browser to it, exchange the
// code, validate the identity token. Any provider with discovery works; the
// presets (presets.go) fill in what Entra and Google need.
//
// Nothing here logs, and no error it returns carries a secret, a code or a
// token: the caller may log them.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Provider is what discovery says about an issuer.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	// How the token endpoint takes the client's credentials. Absent means
	// client_secret_basic, as the specification says.
	TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// Settings is one organization's provider, as the relying party uses it.
type Settings struct {
	// Issuer is what the identity token must carry in iss, and where
	// discovery is fetched from.
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes asked for; openid among them.
	Scopes []string
	// EmailClaim and NameClaim name the claims the address and the display
	// name are read from. EmailFallback is read when EmailClaim is absent
	// (Entra's preferred_username).
	EmailClaim, NameClaim, EmailFallback string
	// RequireEmailVerified refuses a token without email_verified=true. A
	// token that says false is refused whatever this says.
	RequireEmailVerified bool
	// HostedDomain, when set, must be the token's hd claim (Google
	// Workspace), and is sent to the provider as a hint.
	HostedDomain string
}

// Client talks to identity providers. One per process; it caches discovery
// documents and key sets per issuer.
type Client struct {
	http  *http.Client
	local bool

	mu        sync.Mutex
	providers map[string]cached
	keys      *jwk.Cache
}

type cached struct {
	p  Provider
	at time.Time
}

// discoveryTTL is how long a discovery document is trusted before it is
// fetched again.
const discoveryTTL = time.Hour

// maxBody caps what is read from a provider.
const maxBody = 1 << 20

// New is a client. h is for tests; nil is the default, which refuses
// private and loopback addresses unless local. local is a laptop or a test:
// plain http and private addresses are allowed (the stub issuer on the
// compose network).
func New(ctx context.Context, h *http.Client, local bool) (*Client, error) {
	if h == nil {
		h = HTTPClient(local)
	}
	cache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithHTTPClient(h)))
	if err != nil {
		return nil, err
	}
	return &Client{http: h, local: local, providers: map[string]cached{}, keys: cache}, nil
}

// Local is whether plain http issuers are allowed.
func (c *Client) Local() bool { return c.local }

// EntraAuthority is where Entra tenants live. A test points it elsewhere.
const EntraAuthority = "https://login.microsoftonline.com"

// EntraIssuer is the v2 issuer for an Entra tenant under authority. The
// tenant may be a GUID or a verified domain.
func EntraIssuer(authority, tenant string) string {
	return strings.TrimSuffix(authority, "/") + "/" + url.PathEscape(strings.TrimSpace(tenant)) + "/v2.0"
}

// GoogleIssuer is Google's issuer, for Workspace accounts and every other.
const GoogleIssuer = "https://accounts.google.com"

// discoveryURL is where an issuer's configuration is.
func discoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// Discover is the issuer's configuration, cached for an hour, and its keys
// registered for validating tokens.
func (c *Client) Discover(ctx context.Context, issuer string) (Provider, error) {
	c.mu.Lock()
	if e, ok := c.providers[issuer]; ok && time.Since(e.at) < discoveryTTL {
		c.mu.Unlock()
		return e.p, nil
	}
	c.mu.Unlock()
	p, err := c.fetch(ctx, issuer)
	if err != nil {
		return Provider{}, err
	}
	if p.Issuer != issuer {
		return Provider{}, fmt.Errorf("oidc: discover: the document names another issuer")
	}
	if err := c.register(ctx, p); err != nil {
		return Provider{}, err
	}
	return p, nil
}

func (c *Client) register(ctx context.Context, p Provider) error {
	if !c.keys.IsRegistered(ctx, p.JWKSURI) {
		if err := c.keys.Register(ctx, p.JWKSURI, jwk.WithMinInterval(time.Minute)); err != nil {
			return fmt.Errorf("oidc: keys: %w", err)
		}
	}
	c.mu.Lock()
	c.providers[p.Issuer] = cached{p: p, at: time.Now()}
	c.mu.Unlock()
	return nil
}

// fetch is the discovery document, uncached: the real round trip.
func (c *Client) fetch(ctx context.Context, issuer string) (Provider, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL(issuer), nil)
	if err != nil {
		return Provider{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Provider{}, fmt.Errorf("oidc: discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Provider{}, fmt.Errorf("oidc: discover: status %d", resp.StatusCode)
	}
	var p Provider
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&p); err != nil {
		return Provider{}, fmt.Errorf("oidc: discover: not a discovery document")
	}
	if p.Issuer == "" || p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return Provider{}, errors.New("oidc: discover: incomplete configuration")
	}
	for _, u := range []string{p.Issuer, p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI} {
		if err := c.CheckURL(u); err != nil {
			return Provider{}, fmt.Errorf("oidc: discover: %w", err)
		}
	}
	return p, nil
}

// CheckURL refuses anything but an absolute https URL with no credentials
// in it; plain http too when local.
func (c *Client) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("not an absolute URL")
	}
	if u.Scheme != "https" && !(c.local && u.Scheme == "http") {
		return errors.New("not an https URL")
	}
	return nil
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
func AuthorizeURL(p Provider, s Settings, redirectURI, state, nonce string, pkce PKCE) string {
	q := url.Values{
		"client_id":             {s.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(s.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
	}
	if s.HostedDomain != "" {
		q.Set("hd", s.HostedDomain)
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

// tokenResponse is what a token endpoint answers, success or error.
type tokenResponse struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

// post sends a token request with the client's credentials, as the
// provider takes them: in the form when it says it can, else as HTTP basic
// authentication, the specification's default.
func (c *Client) post(ctx context.Context, p Provider, clientID, clientSecret string, form url.Values) (int, tokenResponse, error) {
	basic := !slices.Contains(p.TokenAuthMethods, "client_secret_post")
	if basic {
		form.Del("client_secret")
	} else {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 section 2.3.1: each form-encoded before joining.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, tokenResponse{}, fmt.Errorf("oidc: token: %w", err)
	}
	defer resp.Body.Close()
	var body tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&body); err != nil {
		return resp.StatusCode, tokenResponse{}, fmt.Errorf("oidc: token: status %d, not JSON", resp.StatusCode)
	}
	return resp.StatusCode, body, nil
}

// Exchange trades the code for tokens and validates the identity token.
func (c *Client) Exchange(ctx context.Context, p Provider, s Settings, redirectURI, code, verifier, nonce string) (Claims, error) {
	status, body, err := c.post(ctx, p, s.ClientID, s.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {s.ClientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		return Claims{}, err
	}
	if status != http.StatusOK || body.IDToken == "" {
		if body.Error != "" {
			return Claims{}, fmt.Errorf("%w: %s", ErrRefused, ErrorCode(body.Error))
		}
		return Claims{}, fmt.Errorf("oidc: token: status %d", status)
	}
	return c.validate(ctx, p, s, body.IDToken, nonce)
}

// ErrorCode is a provider's error as something safe to log: a short token
// of the characters an OAuth error code uses.
func ErrorCode(e string) string {
	if len(e) > 64 {
		e = e[:64]
	}
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, e)
}

func (c *Client) validate(ctx context.Context, p Provider, s Settings, raw, nonce string) (Claims, error) {
	set, err := c.keys.Lookup(ctx, p.JWKSURI)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: keys: %w", err)
	}
	// Entra's keys carry no alg: it is inferred from the key, never taken
	// from the token alone, and never none.
	token, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(s.ClientID),
		jwt.WithAcceptableSkew(2*time.Minute),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("iat"),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: identity token: %v", ErrRefused, err)
	}
	var got string
	if err := token.Get("nonce", &got); err != nil || got != nonce {
		return Claims{}, fmt.Errorf("%w: nonce", ErrRefused)
	}
	// A token for several audiences names the one it was issued to.
	if aud, _ := token.Audience(); len(aud) > 1 {
		var azp string
		if err := token.Get("azp", &azp); err != nil || azp != s.ClientID {
			return Claims{}, fmt.Errorf("%w: azp", ErrRefused)
		}
	}
	str := func(name string) string {
		var v any
		if err := token.Get(name, &v); err != nil {
			return ""
		}
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
		return ""
	}
	var claims Claims
	claims.Subject, _ = token.Subject()
	claims.Email = str(s.EmailClaim)
	if claims.Email == "" && s.EmailFallback != "" {
		claims.Email = str(s.EmailFallback)
	}
	claims.Name = str(s.NameClaim)
	claims.JobTitle, claims.Department = str("jobTitle"), str("department")
	claims.EmployeeType, claims.Country, claims.City = str("employeeType"), str("country"), str("city")
	if claims.Subject == "" || claims.Email == "" {
		return Claims{}, fmt.Errorf("%w: no subject or email", ErrRefused)
	}
	// email_verified: a boolean, or the string some providers send.
	var verified any
	switch err := token.Get("email_verified", &verified); {
	case err != nil:
		if s.RequireEmailVerified {
			return Claims{}, fmt.Errorf("%w: email not verified", ErrRefused)
		}
	case verified != true && verified != "true":
		return Claims{}, fmt.Errorf("%w: email not verified", ErrRefused)
	}
	if s.HostedDomain != "" && !strings.EqualFold(str("hd"), s.HostedDomain) {
		return Claims{}, fmt.Errorf("%w: hosted domain", ErrRefused)
	}
	return claims, nil
}
