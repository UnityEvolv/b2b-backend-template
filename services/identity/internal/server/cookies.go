package server

import (
	"context"
	"net/http"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
)

// cookie is one of the cookies this service sets, each named from the
// product's id (config.Cookies). The session cookie is the refresh token,
// on this host only, never a parent domain, so cookie scope ties nothing to
// a domain. The sign-in attempt cookie binds a callback to the browser that
// started it. The impersonation cookie is a platform operator's support
// session (impersonation.go), the refresh token of an impersonation, kept
// apart from their own session so neither replaces the other.
type cookie int

const (
	sessionCookie cookie = iota
	attemptCookie
	impersonationCookie
)

// cookies carries a request's cookies into a strict handler, and the
// handler's Set-Cookie instructions back out. The generated strict server
// hands handlers a context and no ResponseWriter; this is the bridge.
type cookies struct {
	in     map[string]string
	out    []*http.Cookie
	secure bool
	names  config.Cookies
	// The request's user agent, for the session record: which browser or
	// device a session is, so a person can tell them apart when revoking.
	userAgent string
}

// name is what the cookie is called.
func (c *cookies) name(which cookie) string {
	names := c.names
	if names.Session == "" {
		names = config.DefaultCookies
	}
	switch which {
	case attemptCookie:
		return names.SignIn
	case impersonationCookie:
		if names.Impersonation == "" {
			return config.DefaultCookies.Impersonation
		}
		return names.Impersonation
	}
	return names.Session
}

// userAgent is the request's, cut to what the session record holds.
func userAgent(ctx context.Context) string {
	ua := cookiesFrom(ctx).userAgent
	if len(ua) > 300 {
		ua = ua[:300]
	}
	return ua
}

type cookiesKey struct{}

func cookiesFrom(ctx context.Context) *cookies {
	if c, ok := ctx.Value(cookiesKey{}).(*cookies); ok {
		return c
	}
	return &cookies{in: map[string]string{}}
}

// cookieValue is the request's cookie, or "".
func cookieValue(ctx context.Context, which cookie) string {
	c := cookiesFrom(ctx)
	return c.in[c.name(which)]
}

// setCookie schedules a cookie on the response: Secure, HttpOnly, SameSite
// Lax, on this host. maxAge 0 deletes it.
func setCookie(ctx context.Context, which cookie, value string, maxAge time.Duration) {
	c := cookiesFrom(ctx)
	cookie := &http.Cookie{
		Name:     c.name(which),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge <= 0 {
		cookie.MaxAge = -1
	} else {
		cookie.MaxAge = int(maxAge.Seconds())
	}
	c.out = append(c.out, cookie)
}

// withCookies is the middleware: cookies in through the context, cookies out
// as headers written before the status.
func withCookies(secure bool, names config.Cookies) api.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := &cookies{in: map[string]string{}, secure: secure, names: names, userAgent: r.UserAgent()}
			for _, cookie := range r.Cookies() {
				c.in[cookie.Name] = cookie.Value
			}
			cw := &cookieWriter{ResponseWriter: w, cookies: c}
			next.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), cookiesKey{}, c)))
		})
	}
}

type cookieWriter struct {
	http.ResponseWriter
	cookies *cookies
	wrote   bool
}

func (w *cookieWriter) WriteHeader(status int) {
	if !w.wrote {
		w.wrote = true
		for _, c := range w.cookies.out {
			http.SetCookie(w.ResponseWriter, c)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *cookieWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
