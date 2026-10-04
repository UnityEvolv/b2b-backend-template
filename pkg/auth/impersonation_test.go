package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

const (
	operator      = "01922b5e-0000-7000-8000-0000000000e1"
	impersonation = "01922b5e-0000-7000-8000-0000000000e2"
	grantID       = "01922b5e-0000-7000-8000-0000000000e3"
)

// auditLog keeps what the middleware recorded, and fails when told to.
type auditLog struct {
	mu   sync.Mutex
	got  []auth.ImpersonatedRequest
	fail bool
}

func (a *auditLog) RecordImpersonated(_ context.Context, req auth.ImpersonatedRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("audit service down")
	}
	a.got = append(a.got, req)
	return nil
}

func impersonating() auth.Caller {
	return auth.Caller{UserID: user, OrgID: org, MembershipID: member, SessionID: impersonation,
		ImpersonatorID: operator, ImpersonationID: impersonation, ImpersonationGrantID: grantID}
}

func send(h http.Handler, method, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAnImpersonationSessionReadsAndEveryReadIsAudited(t *testing.T) {
	i := issuer(t, issuerName)
	log := &auditLog{}
	h := auth.Require(auth.NewStaticVerifier(issuerName, audience, i.PublicKeys()).WithImpersonationAudit(log), echo)
	raw := token(t, i, impersonating())

	rec := send(h, http.MethodGet, "/v1/organizations/"+org+"/memberships", raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("read: %d %s", rec.Code, rec.Body)
	}
	var got map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	// The person's view, the operator's name on anything recorded.
	if got["user"] != user || got["org"] != org || got["actor"] != "user:"+operator {
		t.Fatalf("context: %v", got)
	}
	if len(log.got) != 1 {
		t.Fatalf("audited %d requests, want 1", len(log.got))
	}
	r := log.got[0]
	if r.Method != http.MethodGet || r.Path != "/v1/organizations/"+org+"/memberships" || r.Refused ||
		r.Caller.ImpersonatorID != operator || r.Caller.ImpersonationID != impersonation || r.Caller.ImpersonationGrantID != grantID {
		t.Fatalf("audited %+v", r)
	}
}

func TestAnImpersonationSessionNeverWrites(t *testing.T) {
	i := issuer(t, issuerName)
	log := &auditLog{}
	served := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })
	h := auth.Require(auth.NewStaticVerifier(issuerName, audience, i.PublicKeys()).WithImpersonationAudit(log), next)
	raw := token(t, i, impersonating())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := send(h, method, "/v1/organizations/"+org+"/projects", raw)
		var e struct{ Code string }
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if rec.Code != http.StatusForbidden || e.Code != auth.CodeImpersonationReadOnly {
			t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
		}
	}
	if served {
		t.Fatal("a write reached the handler")
	}
	// The attempts are in the org's log too.
	if len(log.got) != 4 || !log.got[0].Refused {
		t.Fatalf("audited %+v", log.got)
	}
}

func TestAnImpersonationSessionIsNotServedUnaudited(t *testing.T) {
	i := issuer(t, issuerName)
	raw := token(t, i, impersonating())
	served := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })

	// A service that cannot audit one refuses it.
	h := auth.Require(auth.NewStaticVerifier(issuerName, audience, i.PublicKeys()), next)
	rec := send(h, http.MethodGet, "/v1/organizations/"+org, raw)
	var e struct{ Code string }
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if rec.Code != http.StatusForbidden || e.Code != auth.CodeImpersonationUnsupported {
		t.Fatalf("no auditor: %d %s", rec.Code, rec.Body)
	}

	// An entry that cannot be written: the read does not happen.
	h = auth.Require(auth.NewStaticVerifier(issuerName, audience, i.PublicKeys()).WithImpersonationAudit(&auditLog{fail: true}), next)
	if rec := send(h, http.MethodGet, "/v1/organizations/"+org, raw); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit down: %d %s", rec.Code, rec.Body)
	}
	if served {
		t.Fatal("served without an audit entry")
	}
}

func TestImpersonationClaimsMustHangTogether(t *testing.T) {
	i := issuer(t, issuerName)
	h := auth.Require(auth.NewStaticVerifier(issuerName, audience, i.PublicKeys()).WithImpersonationAudit(&auditLog{}), echo)
	platform := impersonating()
	platform.OrgID = auth.PlatformOrg
	noRun := impersonating()
	noRun.ImpersonationID = ""
	self := impersonating()
	self.ImpersonatorID = user
	malformed := impersonating()
	malformed.ImpersonatorID = "support"
	for name, c := range map[string]auth.Caller{
		"in the platform org":           platform,
		"an impersonator without a run": noRun,
		"impersonating themself":        self,
		"a malformed impersonator":      malformed,
	} {
		t.Run(name, func(t *testing.T) {
			if rec := send(h, http.MethodGet, "/anything", token(t, i, c)); rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
		})
	}
}

func TestAnImpersonationSessionIsNeverAPlatformOperator(t *testing.T) {
	ctx := auth.WithCaller(context.Background(), impersonating())
	if err := auth.RequirePlatform(ctx); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("RequirePlatform: %v", err)
	}
	if err := auth.RefuseImpersonation(ctx); !errors.Is(err, auth.ErrImpersonating) {
		t.Fatalf("RefuseImpersonation: %v", err)
	}
	if !auth.Impersonating(ctx) {
		t.Fatal("not seen as impersonating")
	}
	// The person's own session is not.
	own := auth.WithCaller(context.Background(), auth.Caller{UserID: user, OrgID: org, MembershipID: member})
	if auth.Impersonating(own) || auth.RefuseImpersonation(own) != nil {
		t.Fatal("an ordinary session seen as impersonating")
	}
	// Nor is it the org's: RequireOrg admits it to read what the person may.
	if err := auth.RequireOrg(ctx, org); err != nil {
		t.Fatalf("RequireOrg: %v", err)
	}
}

func TestAuditedPathKeepsIdsAndRouteWordsOnly(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/organizations/" + org + "/memberships":  "/v1/organizations/" + org + "/memberships",
		"/v1/internal/domains/acme.com/organization": "/v1/internal/domains/*/organization",
		"/v1/invites/Zq9-secret_TOKEN":               "/v1/invites/*",
		"/v1/users/someone@example.com":              "/v1/users/*",
	} {
		if got := auth.AuditedPath(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
