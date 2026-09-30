package stubissuer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// OIDC is an OpenID provider for signing in on a laptop: an organization's
// identity provider set to the generic preset with this issuer, client id
// and secret signs in whoever types an address on its page. Nothing is
// checked about the person; everything about the protocol is: the client's
// credentials, the redirect URI, PKCE (S256), and one use per code.
type OIDC struct {
	// Issuer is the issuer URL: what the identity service fetches
	// discovery from and what identity tokens carry.
	Issuer string
	// BrowserURL is where a browser reaches this server, when it differs
	// from Issuer (the compose network: the identity service reaches it by
	// its container name, the browser on localhost). Issuer when empty.
	BrowserURL   string
	ClientID     string
	ClientSecret string

	mu    sync.Mutex
	codes map[string]grant
}

// grant is a code the page handed out, waiting to be exchanged.
type grant struct {
	email, name, nonce, redirectURI, challenge string
	expires                                    time.Time
}

// codeTTL is how long a code waits for its exchange.
const codeTTL = time.Minute

var signInPage = template.Must(template.New("sign-in").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Stub identity provider</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}label{display:block;margin:1rem 0 .25rem}input{width:100%;padding:.5rem}button{margin-top:1rem;padding:.5rem 1rem}</style>
</head><body>
<h1>Stub identity provider</h1>
<p>For a laptop only. Whoever you type is signed in.</p>
<form method="post" action="authorize">
{{range $k, $v := .Params}}<input type="hidden" name="{{$k}}" value="{{$v}}">
{{end}}<label for="email">Email</label><input id="email" name="email" type="email" required value="{{.Hint}}" autofocus>
<label for="name">Name</label><input id="name" name="name">
<button type="submit">Sign in</button>
</form></body></html>`))

// routes adds the provider's endpoints to mux:
//
//	GET  /.well-known/openid-configuration
//	GET  /authorize            the sign-in page
//	POST /authorize            the page's form: a code, back to the client
//	POST /oauth2/token         the code for an identity token
//
// The keys are the issuer's, at /.well-known/jwks.json.
func (o *OIDC) routes(i *Issuer, mux *http.ServeMux) {
	o.codes = map[string]grant{}
	issuer := strings.TrimSuffix(o.Issuer, "/")
	browser := strings.TrimSuffix(o.BrowserURL, "/")
	if browser == "" {
		browser = issuer
	}
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                browser + "/authorize",
			"token_endpoint":                        issuer + "/oauth2/token",
			"jwks_uri":                              issuer + "/.well-known/jwks.json",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"scopes_supported":                      []string{"openid", "email", "profile"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			"code_challenge_methods_supported":      []string{"S256"},
			"claims_supported":                      []string{"sub", "email", "email_verified", "name"},
		})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if msg := o.checkAuthorize(q); msg != "" {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, msg)
			return
		}
		params := map[string]string{}
		for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method", "scope"} {
			params[k] = q.Get(k)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = signInPage.Execute(w, map[string]any{"Params": params, "Hint": q.Get("login_hint")})
	})
	mux.HandleFunc("POST /authorize", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Not a form.")
			return
		}
		f := r.PostForm
		if msg := o.checkAuthorize(f); msg != "" {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, msg)
			return
		}
		addr, err := mail.ParseAddress(strings.TrimSpace(f.Get("email")))
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Not an email address.")
			return
		}
		code := randomString()
		o.mu.Lock()
		o.codes[code] = grant{
			email: strings.ToLower(addr.Address), name: strings.TrimSpace(f.Get("name")), nonce: f.Get("nonce"),
			redirectURI: f.Get("redirect_uri"), challenge: f.Get("code_challenge"), expires: time.Now().Add(codeTTL),
		}
		o.mu.Unlock()
		back, _ := url.Parse(f.Get("redirect_uri"))
		bq := back.Query()
		bq.Set("code", code)
		bq.Set("state", f.Get("state"))
		back.RawQuery = bq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		f := r.PostForm
		id, secret, basic := r.BasicAuth()
		if basic {
			id, _ = url.QueryUnescape(id)
			secret, _ = url.QueryUnescape(secret)
		} else {
			id, secret = f.Get("client_id"), f.Get("client_secret")
		}
		if subtle.ConstantTimeCompare([]byte(id), []byte(o.ClientID)) != 1 || subtle.ConstantTimeCompare([]byte(secret), []byte(o.ClientSecret)) != 1 {
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		if f.Get("grant_type") != "authorization_code" {
			oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
			return
		}
		o.mu.Lock()
		g, ok := o.codes[f.Get("code")]
		delete(o.codes, f.Get("code"))
		o.mu.Unlock()
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || time.Now().After(g.expires) || g.redirectURI != f.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		now := time.Now()
		sub := sha256.Sum256([]byte(g.email))
		b := jwt.NewBuilder().Issuer(issuer).Audience([]string{o.ClientID}).Subject(hex.EncodeToString(sub[:16])).
			IssuedAt(now).Expiration(now.Add(5*time.Minute)).
			Claim("email", g.email).Claim("email_verified", true).Claim("nonce", g.nonce)
		if g.name != "" {
			b = b.Claim("name", g.name)
		}
		token, err := b.Build()
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), i.private))
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"id_token": string(signed), "access_token": randomString(), "token_type": "Bearer", "expires_in": 300})
	})
}

// checkAuthorize is what is wrong with an authorization request, or "".
func (o *OIDC) checkAuthorize(q url.Values) string {
	switch {
	case q.Get("client_id") != o.ClientID:
		return "Unknown client_id."
	case q.Get("response_type") != "" && q.Get("response_type") != "code":
		return "Only response_type=code."
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		return "PKCE (S256) is required."
	case q.Get("nonce") == "" || q.Get("state") == "":
		return "A state and a nonce are required."
	case !strings.Contains(" "+q.Get("scope")+" ", " openid "):
		return "The openid scope is required."
	}
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "Not a redirect_uri."
	}
	return ""
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, status, map[string]string{"error": code})
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
