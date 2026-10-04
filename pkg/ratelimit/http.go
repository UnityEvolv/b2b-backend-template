package ratelimit

import (
	"math"
	"net/http"
	"strconv"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// KeyFunc picks the bucket for a request. ok is false when the request has
// nothing to key by (a membership rule on a token without one), in which case
// the rule does not apply to it.
type KeyFunc func(*http.Request) (key string, ok bool)

// ByIP keys by the client address: behind the platform's load balancer, the
// one it saw, never an entry a client wrote (httpx.ClientIP).
func ByIP(r *http.Request) (string, bool) {
	host := httpx.ClientIP(r)
	return "ip:" + host, host != ""
}

// ByUser keys by the authenticated user. A request made with an API key or
// a personal access token counts against the key, so one script never
// spends its person's allowance, nor another key's.
func ByUser(r *http.Request) (string, bool) {
	if k, ok := auth.KeyFrom(r.Context()); ok {
		return "key:" + k.ID, true
	}
	c, ok := auth.CallerFrom(r.Context())
	return "user:" + c.UserID, ok && c.UserID != ""
}

// ByMembership keys by the caller's membership: one person in one org. A
// key counts against itself, as ByUser.
func ByMembership(r *http.Request) (string, bool) {
	if k, ok := auth.KeyFrom(r.Context()); ok {
		return "key:" + k.ID, true
	}
	c, ok := auth.CallerFrom(r.Context())
	return "mbr:" + c.MembershipID, ok && c.MembershipID != ""
}

// ByOrg keys by the caller's org, for limits a whole org shares, keys
// included.
func ByOrg(r *http.Request) (string, bool) {
	if k, ok := auth.KeyFrom(r.Context()); ok {
		return "org:" + k.OrgID, true
	}
	c, ok := auth.CallerFrom(r.Context())
	return "org:" + c.OrgID, ok && c.OrgID != ""
}

// Combine keys by all of fns together, such as IP and user.
func Combine(fns ...KeyFunc) KeyFunc {
	return func(r *http.Request) (string, bool) {
		key := ""
		for _, fn := range fns {
			part, ok := fn(r)
			if !ok {
				return "", false
			}
			key += part + "|"
		}
		return key, true
	}
}

// Bound is a rule and what it counts by.
type Bound struct {
	Rule Rule
	Key  KeyFunc
}

// On binds rule to key: one line per endpoint in a service's route table.
func On(rule Rule, key KeyFunc) Bound { return Bound{Rule: rule, Key: key} }

// Routes limits each route by the rule declared for its pattern:
//
//	limiter.Routes(map[string]ratelimit.Bound{
//	    "GET /v1/organizations/{org_id}": ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
//	})
//
// It runs after routing, so it goes in the generated server's Middlewares.
func (l *Limiter) Routes(bounds map[string]Bound) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bound, ok := bounds[r.Pattern]
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			l.Wrap(bound, next).ServeHTTP(w, r)
		})
	}
}

// Wrap limits every request to next by one bound, such as a per-IP ceiling
// in front of authentication.
func (l *Limiter) Wrap(bound Bound, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := bound.Key(r)
		if !ok || Bypassed(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		v, err := l.Take(r.Context(), bound.Rule, key)
		if err != nil {
			httpx.WriteError(w, http.StatusServiceUnavailable, httpx.CodeUnavailable, "Try again in a moment.")
			return
		}
		w.Header().Set("RateLimit-Limit", strconv.Itoa(bound.Rule.Limit))
		w.Header().Set("RateLimit-Remaining", strconv.Itoa(v.Remaining))
		if !v.Allowed {
			l.Refuse(w, r, bound.Rule, v)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Refuse answers 429 with Retry-After, and records the hit. A spike of these
// is an attack or a bug, so each one is logged at warn for error tracking.
func (l *Limiter) Refuse(w http.ResponseWriter, r *http.Request, rule Rule, v Verdict) {
	seconds := int(math.Ceil(v.RetryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	// alert=true: a spike of these is an attack or a bug, so error tracking sees it.
	l.logger.WarnContext(r.Context(), "rate limited", "rule", rule.Name, "route", r.Pattern, "retry_after_s", seconds, "alert", true)
	httpx.WriteError(w, http.StatusTooManyRequests, httpx.CodeRateLimited, "Too many requests. Try again shortly.")
}
