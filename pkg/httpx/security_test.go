package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// The agreed set. A refactor that drops one fails here, not in a pen test.
var requiredHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	mux := httpx.NewMux()
	mux.Handle("GET /ok", ok)
	mux.HandleFunc("GET /fail", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "boom")
	})
	h := httpx.SecurityHeaders(mux)

	for _, path := range []string{"/ok", "/fail", "/nothing-here"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		for _, name := range requiredHeaders {
			if rec.Header().Get(name) == "" {
				t.Errorf("%s (status %d): missing %s", path, rec.Code, name)
			}
		}
	}
	if got := httpx.SecurityHeaderNames(); len(got) != len(requiredHeaders) {
		t.Errorf("SecurityHeaders sets %v; this test expects %v — update both together", got, requiredHeaders)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("API CSP %q must forbid everything, including framing", csp)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options %q", rec.Header().Get("X-Frame-Options"))
	}
}

func TestCORSAllowsOnlyTheConfiguredOrigins(t *testing.T) {
	h := httpx.CORS([]string{"https://b2bapp.example", "http://localhost:5173"}, ok)

	send := func(method, origin, preflightFor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/v1/things", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if preflightFor != "" {
			req.Header.Set("Access-Control-Request-Method", preflightFor)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// A known origin gets exactly itself back, never a wildcard.
	rec := send(http.MethodGet, "https://b2bapp.example", "")
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://b2bapp.example" {
		t.Errorf("known origin: Allow-Origin %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("known origin: the session cookie needs credentialed answers, got %q", rec.Header().Get("Access-Control-Allow-Credentials"))
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Expose-Headers"), "Retry-After") {
		t.Errorf("rate-limit headers must be readable by the app: %q", rec.Header().Get("Access-Control-Expose-Headers"))
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Errorf("Vary %q", rec.Header().Get("Vary"))
	}

	// A preflight from a known origin succeeds and names what is allowed.
	rec = send(http.MethodOptions, "http://localhost:5173", "POST")
	if rec.Code != http.StatusNoContent || (!strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Idempotency-Key") || !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "X-Captcha-Token")) {
		t.Errorf("preflight: %d %v", rec.Code, rec.Header())
	}

	// An unknown origin: no permission, and its preflight is refused outright.
	for _, origin := range []string{"https://evil.example", "https://b2bapp.example.evil", "HTTPS://B2BAPP.EXAMPLE/"} {
		rec = send(http.MethodGet, origin, "")
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s was allowed", origin)
		}
		if rec = send(http.MethodOptions, origin, "POST"); rec.Code != http.StatusForbidden {
			t.Errorf("%s preflight: %d, want 403", origin, rec.Code)
		}
	}

	// No Origin at all (curl, another service): plain request, no CORS headers.
	rec = send(http.MethodGet, "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("no origin: %d %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSNeverWildcards(t *testing.T) {
	h := httpx.CORS([]string{"*"}, ok)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anyone.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("a '*' in configuration must not open the API: got %q", got)
	}
}

func TestCookiesAreAlwaysHardened(t *testing.T) {
	rec := httptest.NewRecorder()
	httpx.SetCookie(rec, "session", "abc", time.Hour)
	c := rec.Result().Cookies()[0]
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" {
		t.Fatalf("cookie %+v", c)
	}
}
