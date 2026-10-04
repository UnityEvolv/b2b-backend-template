package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Support impersonation (docs/impersonation.md).
//
// A platform operator may see an org as one of its people sees it, with the
// Owner's consent or under the org's standing support access. The identity
// service starts the session; its access token is the person's, marked
// with ClaimImpersonator. What such a token may do is decided here, in the
// middleware every service mounts, not by each handler:
//
//   - It reads and never writes: a method that is not safe is refused,
//     except a write named in impersonationWrites, which is empty.
//   - A write that changes security settings, billing or ownership is
//     refused even if it is ever named there (neverWhileImpersonating).
//   - Every request it makes, a read or a refused write, is audited in the
//     org's own log before the handler runs; one that cannot be recorded is
//     not served.
//   - It is never a platform operator (RequirePlatform), and never another
//     service's or the platform org's.

// The error codes an impersonation session meets.
const (
	// CodeImpersonationReadOnly is a write refused because a platform
	// operator is behind the token.
	CodeImpersonationReadOnly = "impersonation.read_only"
	// CodeImpersonationUnsupported is a service not set up to audit an
	// impersonation session, which therefore refuses it.
	CodeImpersonationUnsupported = "impersonation.unsupported"
)

// ImpersonationAuditor records one request an impersonation session made,
// in the org's audit log. pkg/audit.Impersonation is the one every service
// uses; a failure refuses the request.
type ImpersonationAuditor interface {
	RecordImpersonated(ctx context.Context, req ImpersonatedRequest) error
}

// ImpersonatedRequest is what is recorded of a request made while
// impersonating. Ids and the shape of the request only: the path has any
// segment that is neither an id nor a plain word replaced, and the query
// and body are never kept.
type ImpersonatedRequest struct {
	Caller Caller
	Method string
	Path   string
	// Refused is true for a write the session was refused.
	Refused bool
}

// WithImpersonationAudit is v admitting impersonation sessions, each
// request recorded by a. Without it, an impersonation token is refused:
// a service that cannot audit one does not serve one.
func (v *Verifier) WithImpersonationAudit(a ImpersonationAuditor) *Verifier {
	v.auditor = a
	return v
}

// Impersonating reports whether the request in ctx is an impersonation
// session's.
func Impersonating(ctx context.Context) bool {
	c, ok := CallerFrom(ctx)
	return ok && c.Impersonated()
}

// ErrImpersonating is an action an impersonation session may never take,
// whatever the method: making a key, starting another impersonation.
var ErrImpersonating = errors.New("auth: not while impersonating")

// RefuseImpersonation is ErrImpersonating when the request in ctx is an
// impersonation session's: for an action refused in its own right, on top
// of the middleware's read-only rule.
func RefuseImpersonation(ctx context.Context) error {
	if Impersonating(ctx) {
		return ErrImpersonating
	}
	return nil
}

// ImpersonationClaims is the claims an issuer adds for c's impersonation,
// none when c is nobody's.
func ImpersonationClaims(c Caller) map[string]string {
	if c.ImpersonatorID == "" {
		return nil
	}
	out := map[string]string{ClaimImpersonator: c.ImpersonatorID, ClaimImpersonation: c.ImpersonationID}
	if c.ImpersonationGrantID != "" {
		out[ClaimImpersonationGrant] = c.ImpersonationGrantID
	}
	return out
}

// checkImpersonation refuses a token whose impersonation claims do not
// hang together: an impersonator comes with an impersonation, both with an
// org that is a customer's, never the platform org.
func checkImpersonation(c Caller) error {
	if c.ImpersonatorID == "" {
		if c.ImpersonationID != "" || c.ImpersonationGrantID != "" {
			return fmt.Errorf("%w: an impersonation without an impersonator", ErrUnauthenticated)
		}
		return nil
	}
	switch {
	case c.ImpersonationID == "":
		return fmt.Errorf("%w: an impersonator without an impersonation", ErrUnauthenticated)
	case c.OrgID == "" || strings.EqualFold(c.OrgID, PlatformOrg):
		return fmt.Errorf("%w: an impersonation is in a customer's org", ErrUnauthenticated)
	case strings.EqualFold(c.ImpersonatorID, c.UserID):
		return fmt.Errorf("%w: nobody impersonates themself", ErrUnauthenticated)
	}
	return nil
}

// impersonatedWrite is a write an impersonation session may make: a method
// and a path pattern.
type impersonatedWrite struct {
	Method string
	Path   *regexp.Regexp
}

// impersonationWrites is the writes an impersonation session may make.
// None: support sees, it does not act. Each the UI makes as a side effect
// of reading (marking a notification read, say) is refused like any other
// write, and the app shows the refusal; the person's own state is theirs
// to change. A write mode added later names its writes here, and
// neverWhileImpersonating still wins.
var impersonationWrites []impersonatedWrite

// neverWhileImpersonating is the path segments of writes refused to an
// impersonation session even when impersonationWrites names them: security
// settings (roles, permissions, single sign-on, sessions, second factors,
// keys, SCIM, webhook endpoints that send the org's events out, support
// access itself), billing and plans, ownership and the
// org's existence, and the person's own account.
var neverWhileImpersonating = []string{
	// Security settings.
	"permissions", "role", "identity-provider", "session-policy", "sessions", "mfa",
	"api-keys", "personal-access-tokens", "scim", "support-access",
	"webhook-endpoints", "webhook-deliveries", "rotate-secret",
	"impersonation-grants", "impersonations", "domain", "data-keys", "retention",
	// Billing and plans.
	"billing", "plan", "plan-change", "plan-overrides",
	// Ownership, membership and the org itself.
	"ownership-transfers", "status", "leave", "close", "reopen", "exports", "imports",
	// The person's account.
	"me", "email", "password", "deletion",
}

// safeMethod is a method that reads.
func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// ImpersonationMay reports whether an impersonation session may make a
// request: any read, and a write only when impersonationWrites names it
// and it touches nothing in neverWhileImpersonating.
func ImpersonationMay(method, path string) bool {
	if safeMethod(method) {
		return true
	}
	for _, seg := range strings.Split(path, "/") {
		if slices.Contains(neverWhileImpersonating, seg) {
			return false
		}
	}
	for _, w := range impersonationWrites {
		if w.Method == method && w.Path.MatchString(path) {
			return true
		}
	}
	return false
}

// word is a path segment kept as it is in the audit entry: a fixed part of
// a route. Anything else that is not an id is replaced.
var word = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)

// AuditedPath is path as recorded: every segment an id or a word of the
// route, anything else (a domain, an address, a token) as "*".
func AuditedPath(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s == "" || word.MatchString(s) || uuid.Validate(s) == nil {
			continue
		}
		segs[i] = "*"
	}
	return strings.Join(segs, "/")
}

// impersonated serves a request from an impersonation session: refused
// without an auditor, recorded, and refused when it writes.
func (v *Verifier) impersonated(w http.ResponseWriter, r *http.Request, c Caller, next http.Handler) {
	if v.auditor == nil {
		httpx.WriteError(w, http.StatusForbidden, CodeImpersonationUnsupported, "This service does not serve support sessions.")
		return
	}
	allowed := ImpersonationMay(r.Method, r.URL.Path)
	err := v.auditor.RecordImpersonated(r.Context(), ImpersonatedRequest{Caller: c, Method: r.Method, Path: AuditedPath(r.URL.Path), Refused: !allowed})
	if err != nil {
		// Not served: a request nobody can account for does not happen.
		errtrack.Capture(r.Context(), err)
		httpx.WriteError(w, http.StatusServiceUnavailable, httpx.CodeUnavailable, "Try again in a moment.")
		return
	}
	if !allowed {
		httpx.WriteError(w, http.StatusForbidden, CodeImpersonationReadOnly, "A support session can look but not change anything.")
		return
	}
	next.ServeHTTP(w, r)
}
