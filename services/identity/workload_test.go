package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// The deployed token endpoint: only the service's own account, with a
// verified platform token for this audience, gets that service's token.
func TestWorkloadTokens(t *testing.T) {
	accounts := workloadAccounts{prefix: "dev-", domain: "example-project.iam.gserviceaccount.com"}
	tokens := map[string]workloadIdentity{
		"billing":  {Email: "dev-billing@example-project.iam.gserviceaccount.com", EmailVerified: true},
		"web":      {Email: "dev-web-app@example-project.iam.gserviceaccount.com", EmailVerified: true},
		"deploy":   {Email: "dev-deploy@example-project.iam.gserviceaccount.com", EmailVerified: true},
		"stranger": {Email: "dev-billing@someone-else.iam.gserviceaccount.com", EmailVerified: true},
		"unproven": {Email: "dev-billing@example-project.iam.gserviceaccount.com", EmailVerified: false},
	}
	verify := func(_ context.Context, token, audience string) (workloadIdentity, error) {
		if audience != "https://api.example/identity" {
			return workloadIdentity{}, errors.New("wrong audience")
		}
		who, ok := tokens[token]
		if !ok {
			return workloadIdentity{}, errors.New("not a token")
		}
		return who, nil
	}
	var issued []auth.Caller
	issue := func(c auth.Caller, _ time.Duration) (string, error) {
		issued = append(issued, c)
		return "signed", nil
	}
	h := workloadTokens(issue, verify, "https://api.example/identity", accounts)
	ask := func(token, service string) int {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"service":"`+service+`"}`))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	cases := []struct {
		token, service string
		want           int
	}{
		{"billing", "billing", http.StatusOK},
		{"billing", "identity", http.StatusForbidden}, // its own service only
		{"web", "web-app", http.StatusForbidden},      // a web app is no service
		{"deploy", "deploy", http.StatusForbidden},    // nor is the deployer
		{"stranger", "billing", http.StatusForbidden}, // another project's account
		{"unproven", "billing", http.StatusUnauthorized},
		{"forged", "billing", http.StatusUnauthorized},
		{"", "billing", http.StatusUnauthorized},
	}
	for _, c := range cases {
		if got := ask(c.token, c.service); got != c.want {
			t.Errorf("%s asking for %s: %d, want %d", c.token, c.service, got, c.want)
		}
	}
	if len(issued) != 1 || issued[0].Service != "billing" {
		t.Errorf("issued %v, want one token for billing", issued)
	}
}
