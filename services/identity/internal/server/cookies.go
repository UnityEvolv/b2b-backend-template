package server

import (
	"context"
	"net/http"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
)

// The session cookie: the refresh token, on this host only, never a parent
// domain, so cookie scope ties nothing to a domain. It is the only cookie
// the platform sets. The sign-in attempt cookie binds a callback to the
// browser that started it.
const (
	sessionCookie = "uo_session"
	attemptCookie = "uo_signin"
)

// cookies carries a request's cookies into a strict handler, and the
// handler's Set-Cookie instructions back out. The generated strict server
// hands handlers a context and no ResponseWriter; this is the bridge.
type cookies struct {
	in     map[string]string
	out    []*http.Cookie
	secure bool
	// The request's user agent, for the session record: which browser or
	// device a session is, so a person can tell them apart when revoking.
	userAgent string
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
func cookieValue(ctx context.Context, name string) string {
	return cookiesFrom(ctx).in[name]
}

// setCookie schedules a cookie on the response: Secure, HttpOnly, SameSite
// Lax, on this host. maxAge 0 deletes it.
func setCookie(ctx context.Context, name, value string, maxAge time.Duration) {
	c := cookiesFrom(ctx)
	cookie := &http.Cookie{
		Name:     name,
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
func withCookies(secure bool) api.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := &cookies{in: map[string]string{}, secure: secure, userAgent: r.UserAgent()}
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
