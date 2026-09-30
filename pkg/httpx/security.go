package httpx

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The headers every API response carries. An API serves JSON to
// scripts, never a page to a browser, so the policy is the strictest one: no
// framing, no content of any kind, no sniffing, no referrer.
var apiHeaders = map[string]string{
	"Content-Security-Policy":    "default-src 'none'; frame-ancestors 'none'",
	"Strict-Transport-Security":  "max-age=63072000; includeSubDomains",
	"X-Content-Type-Options":     "nosniff",
	"X-Frame-Options":            "DENY",
	"Referrer-Policy":            "no-referrer",
	"Permissions-Policy":         "camera=(), microphone=(), display-capture=(), geolocation=(), payment=(), usb=()",
	"Cross-Origin-Opener-Policy": "same-origin",
}

// SecurityHeaderNames is every header SecurityHeaders sets, for the test
// that fails when one goes missing.
func SecurityHeaderNames() []string {
	names := make([]string, 0, len(apiHeaders))
	for name := range apiHeaders {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// SecurityHeaders adds the API's security headers to every response, whatever
// the status and whoever sent it. It goes outermost, so even a refusal from
// the rate limiter or the auth middleware carries them.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for name, value := range apiHeaders {
			h.Set(name, value)
		}
		next.ServeHTTP(w, r)
	})
}

// CORS allows the app origins, and only them, to call the API from a browser.
//
// origins is the exact list from configuration: the three web apps and the
// desktop scheme, derived from the base hostname. Never a wildcard, and never
// reflected: a request from an origin not in the list gets no CORS headers at
// all, so the browser refuses to hand the response to the page.
func CORS(origins []string, next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[strings.TrimSuffix(strings.ToLower(o), "/")] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every response varies by origin, whether or not this one had one, so
		// a cache never serves one origin's headers to another.
		w.Header().Add("Vary", "Origin")

		origin := r.Header.Get("Origin")
		if origin == "" || !allowed[strings.ToLower(origin)] {
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				// A preflight from somewhere we do not know: answer it, but
				// without permission. The browser then blocks the real request.
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		// The session cookie lives on the API host, and the apps are other
		// origins: without this the browser drops every credentialed answer,
		// sign-in and refresh included. Safe because the origin is echoed
		// only when it is one of ours, never a wildcard.
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Access-Control-Expose-Headers", "X-Request-Id, RateLimit-Limit, RateLimit-Remaining, Retry-After")

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Request-Id, X-Captcha-Token")
			h.Set("Access-Control-Max-Age", strconv.Itoa(int((10 * time.Minute).Seconds())))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SetCookie is the one way a service sets a cookie: always Secure, HttpOnly
// and SameSite, scoped to the API host, never a parent domain.
func SetCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
