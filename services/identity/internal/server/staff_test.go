package server_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// Staff sign-in, on the server side: a platform
// operator cannot get a session without a second factor, whatever the
// platform org's stored policy says, and their wrong passwords are audited
// on the platform's log while a customer's are not.
func TestStaffNeedASecondFactorAndFailuresAreAudited(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	platform := uuid.MustParse(auth.PlatformOrg)
	f.account(t, "operator@example.com", platform, "operators-long-password")
	f.account(t, "carol@example.com", acme, "carols-long-password")

	code, out := signInLocal(t, b, "operator@example.com", "operators-long-password")
	if code != http.StatusAccepted || out["mfa"] != "enroll" {
		t.Fatalf("operator without a factor: %d %v", code, out)
	}
	// A customer in an org with no policy still signs straight in.
	if code, out := signInLocal(t, b, "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Fatalf("customer: %d %v", code, out)
	}

	if code, _ := signInLocal(t, b, "operator@example.com", "wrong-password-here"); code != http.StatusUnauthorized {
		t.Fatalf("operator wrong password: %d", code)
	}
	if code, _ := signInLocal(t, b, "carol@example.com", "wrong-password-here"); code != http.StatusUnauthorized {
		t.Fatalf("customer wrong password: %d", code)
	}
	if n := f.audited("session.sign_in_failed"); n != 1 {
		t.Errorf("failed sign-ins audited %d times, want only the operator's", n)
	}
}

// A suspended org's members get no session there.
// An open session loses it at the next refresh, a fresh sign-in is refused
// with its own reason, switching into it is refused, and reactivation
// lets them back in.
func TestSuspendedOrgsGiveNoSession(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	f.account(t, "carol@example.com", acme, "carols-long-password")
	if code, out := signInLocal(t, b, "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Fatalf("before suspension: %d %v", code, out)
	}
	f.orgs["suspended:"+acme.String()] = acme

	rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	if rec.Code != http.StatusUnauthorized || body(t, rec)["code"] != "organization.suspended" {
		t.Errorf("refresh while suspended: %d %s", rec.Code, rec.Body.String())
	}
	if code, out := signInLocal(t, b, "carol@example.com", "carols-long-password"); code != http.StatusUnauthorized || out["code"] != "organization.suspended" {
		t.Errorf("sign-in while suspended: %d %v", code, out)
	}

	delete(f.orgs, "suspended:"+acme.String())
	if code, out := signInLocal(t, b, "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Fatalf("after reactivation: %d %v", code, out)
	}
	// With a second org, suspending one moves the person and refuses the switch back.
	f.users.add("carol@example.com", globex, "active", nil)
	f.orgs["suspended:"+globex.String()] = globex
	rec = b.do(http.MethodPost, "/v1/session/switch", "", map[string]any{"org_id": globex})
	if rec.Code != http.StatusForbidden || body(t, rec)["code"] != "organization.suspended" {
		t.Errorf("switch into a suspended org: %d %s", rec.Code, rec.Body.String())
	}
}
