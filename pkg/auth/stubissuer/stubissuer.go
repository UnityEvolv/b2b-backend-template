// Package stubissuer mints tokens for local development and tests, until the
// identity service issues real ones.
//
// It signs with a key it generates at start and publishes the public half as a
// JWKS, exactly as the real issuer will, so services verify its tokens with the
// same code path. It checks nothing about who asks: never run it anywhere but
// a laptop or a test. Services refuse its tokens anywhere else because their
// configured issuer name will not match.
package stubissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Issuer signs tokens.
type Issuer struct {
	issuer, audience string
	private          jwk.Key
	public           jwk.Set
	oidc             *OIDC
}

// WithOIDC makes the issuer an OpenID provider too, for signing in through
// an organization's identity provider on a laptop (oidc.go). Before Handler.
func (i *Issuer) WithOIDC(o *OIDC) *Issuer {
	i.oidc = o
	return i
}

// New is an issuer with a fresh ES256 key.
func New(issuer, audience string) (*Issuer, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	private, err := jwk.Import(raw)
	if err != nil {
		return nil, err
	}
	if err := jwk.AssignKeyID(private); err != nil {
		return nil, err
	}
	if err := private.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(private); err != nil {
		return nil, err
	}
	public, err := jwk.PublicSetOf(set)
	if err != nil {
		return nil, err
	}
	return &Issuer{issuer: issuer, audience: audience, private: private, public: public}, nil
}

// PublicKeys is the JWKS a verifier checks against.
func (i *Issuer) PublicKeys() jwk.Set { return i.public }

// Issue is a signed token for c, valid for ttl.
func (i *Issuer) Issue(c auth.Caller, ttl time.Duration) (string, error) {
	return i.issue(c, time.Now(), ttl)
}

func (i *Issuer) issue(c auth.Caller, now time.Time, ttl time.Duration) (string, error) {
	subject := c.UserID
	if c.Service != "" {
		subject = "service:" + c.Service
	}
	b := jwt.NewBuilder().
		Issuer(i.issuer).
		Audience([]string{i.audience}).
		Subject(subject).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(ttl)).
		JwtID(uuid.NewString())
	if c.Service != "" {
		b = b.Claim(auth.ClaimService, c.Service)
	}
	if c.OrgID != "" {
		b = b.Claim(auth.ClaimOrg, c.OrgID).Claim(auth.ClaimMembership, c.MembershipID)
	}
	if c.SessionID != "" {
		b = b.Claim(auth.ClaimSession, c.SessionID)
	}
	for k, v := range auth.ImpersonationClaims(c) {
		b = b.Claim(k, v)
	}
	token, err := b.Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), i.private))
	return string(signed), err
}

// IssueAt is Issue with a chosen clock, for testing expiry.
func (i *Issuer) IssueAt(c auth.Caller, now time.Time, ttl time.Duration) (string, error) {
	return i.issue(c, now, ttl)
}

type tokenRequest struct {
	UserID       string `json:"user_id"`
	OrgID        string `json:"org_id"`
	MembershipID string `json:"membership_id"`
	// Service, when set, mints a service token for that service instead.
	Service    string `json:"service"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// Handler serves the JWKS and a token endpoint:
//
//	GET  /.well-known/jwks.json
//	POST /token  {"user_id", "org_id", "membership_id", "ttl_seconds"}
//	POST /token  {"service": "organization"}   a service token
//
// Any id left out is made up, so an empty body is a valid request. With
// WithOIDC, the OpenID provider's endpoints too.
func (i *Issuer) Handler() http.Handler {
	mux := httpx.NewMux()
	if i.oidc != nil {
		i.oidc.routes(i, mux)
	}
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, i.public)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Body is not JSON.")
				return
			}
		}
		if req.Service != "" {
			if !auth.KnownService(req.Service) {
				httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "No such service.")
				return
			}
			ttl := time.Duration(req.TTLSeconds) * time.Second
			if ttl <= 0 || ttl > 24*time.Hour {
				ttl = time.Hour
			}
			token, err := i.Issue(auth.Caller{Service: req.Service}, ttl)
			if err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, fmt.Sprint("Could not sign: ", err))
				return
			}
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(ttl.Seconds()), "service": req.Service})
			return
		}
		fill := func(id *string) {
			if *id == "" {
				*id = uuid.NewString()
			}
		}
		fill(&req.UserID)
		if req.OrgID != "" {
			fill(&req.MembershipID)
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 || ttl > 24*time.Hour {
			ttl = 8 * time.Hour
		}
		c := auth.Caller{UserID: req.UserID, OrgID: req.OrgID, MembershipID: req.MembershipID, SessionID: uuid.NewString()}
		token, err := i.Issue(c, ttl)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, fmt.Sprint("Could not sign: ", err))
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  token,
			"token_type":    "Bearer",
			"expires_in":    int(ttl.Seconds()),
			"user_id":       c.UserID,
			"org_id":        c.OrgID,
			"membership_id": c.MembershipID,
		})
	})
	return mux
}
