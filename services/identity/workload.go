package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// The deployed /token: a service proves who it is
// with the identity token its platform signs for its own service account,
// and gets this platform's service token in exchange. On Cloud Run that is
// a Google-signed OpenID token for the service's account, fetched from the
// metadata server, whose audience is this service's public URL.
//
// The account must be exactly "<prefix><service>@<domain>", where prefix and
// domain come from configuration ("dev-" and the project's IAM domain), and
// the service must be one the platform knows. Nothing else gets a token: not
// a web app's account, not the deploy account, not anyone with a Google token
// for another audience.

// workloadIdentity is who a verified platform token says the caller is.
type workloadIdentity struct {
	Email         string
	EmailVerified bool
}

// verifyWorkload checks a platform identity token for audience.
type verifyWorkload func(ctx context.Context, token, audience string) (workloadIdentity, error)

// workloadAccounts maps a service account email to the service it runs.
type workloadAccounts struct {
	prefix, domain string
}

func (a workloadAccounts) service(email string) (string, bool) {
	local, domain, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok || domain != strings.ToLower(a.domain) || !strings.HasPrefix(local, strings.ToLower(a.prefix)) {
		return "", false
	}
	name := strings.TrimPrefix(local, strings.ToLower(a.prefix))
	return name, name != "" && auth.KnownService(name)
}

// workloadTokens is POST /token for deployed services.
//
//	POST /token {"service": "billing"}   Authorization: Bearer <platform identity token>
func workloadTokens(issue func(auth.Caller, time.Duration) (string, error), verify verifyWorkload, audience string, accounts workloadAccounts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthenticated, "Present your platform identity token.")
			return
		}
		var req struct {
			Service string `json:"service"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Service == "" {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Name the service.")
			return
		}
		who, err := verify(r.Context(), raw, audience)
		if err != nil || !who.EmailVerified {
			httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthenticated, "That identity token is not valid for this service.")
			return
		}
		name, known := accounts.service(who.Email)
		if !known || name != req.Service {
			httpx.WriteError(w, http.StatusForbidden, httpx.CodeForbidden, "That account does not run this service.")
			return
		}
		ttl := time.Hour
		token, err := issue(auth.Caller{Service: name}, ttl)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Could not sign.")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": token, "token_type": "Bearer", "expires_in": int(ttl.Seconds()), "service": name,
		})
	})
}
