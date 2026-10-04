package auth

import (
	"net/http"
	"regexp"
	"testing"
)

// A write mode added later names its writes in impersonationWrites; one
// that touches security settings, billing or ownership is still refused.
func TestSecurityBillingAndOwnershipWritesAreRefusedEvenWhenAllowed(t *testing.T) {
	saved := impersonationWrites
	t.Cleanup(func() { impersonationWrites = saved })
	impersonationWrites = []impersonatedWrite{{Method: http.MethodPost, Path: regexp.MustCompile(`.*`)}, {Method: http.MethodPut, Path: regexp.MustCompile(`.*`)}, {Method: http.MethodDelete, Path: regexp.MustCompile(`.*`)}}

	org := "/v1/organizations/01922b5e-0000-7000-8000-0000000000d2"
	for _, path := range []string{
		org + "/permissions", org + "/memberships/01922b5e-0000-7000-8000-0000000000d3/role",
		org + "/identity-provider", org + "/session-policy", org + "/api-keys", org + "/personal-access-tokens",
		org + "/scim/tokens", org + "/support-access", org + "/impersonation-grants", org + "/domain/verify",
		org + "/billing/band", org + "/plan-change", org + "/plan-overrides/limit/seats",
		org + "/ownership-transfers", org + "/close", org + "/memberships/01922b5e-0000-7000-8000-0000000000d3/status",
		org + "/webhook-endpoints", org + "/webhook-endpoints/01922b5e-0000-7000-8000-0000000000d4/rotate-secret",
		org + "/webhook-deliveries/01922b5e-0000-7000-8000-0000000000d5/resend",
		"/v1/mfa/totp", "/v1/me/email", "/v1/local/password", "/v1/sessions",
	} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			if ImpersonationMay(method, path) {
				t.Errorf("%s %s allowed", method, path)
			}
		}
	}
	// What the write mode named and is not on the list goes through.
	if !ImpersonationMay(http.MethodPost, org+"/projects") {
		t.Error("an allowed write refused")
	}
}

func TestTheTemplateAllowsNoWriteWhileImpersonating(t *testing.T) {
	if len(impersonationWrites) != 0 {
		t.Fatalf("impersonationWrites is %v: support sessions are read-only", impersonationWrites)
	}
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if !ImpersonationMay(m, "/v1/organizations/x/billing") {
			t.Errorf("%s refused: reading is what a support session is for", m)
		}
	}
	if ImpersonationMay(http.MethodPost, "/v1/organizations/x/notifications/read") {
		t.Error("a write allowed")
	}
}

func TestAnImpersonationWithoutAnImpersonatorIsRefused(t *testing.T) {
	c := Caller{UserID: "01922b5e-0000-7000-8000-0000000000d1", OrgID: "01922b5e-0000-7000-8000-0000000000d2",
		MembershipID: "01922b5e-0000-7000-8000-0000000000d3", ImpersonationID: "01922b5e-0000-7000-8000-0000000000e2"}
	if checkImpersonation(c) == nil {
		t.Fatal("an impersonation claim without an impersonator was accepted")
	}
}
