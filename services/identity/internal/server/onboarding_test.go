package server_test

import (
	"net/http"
	"testing"
)

// The identity service's onboarding steps are derived from its rows when
// the organization service asks, and only it may ask.
func TestOnboardingStepsAreDerivedFromInvitesAndTheProvider(t *testing.T) {
	f := newAPI(t)
	org := f.service("organization")
	step := func(id string) (int, map[string]any) {
		t.Helper()
		return f.call(t, http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/onboarding/"+id, org, nil)
	}
	for _, id := range []string{"invite_teammates", "set_up_sso"} {
		if status, out := step(id); status != http.StatusOK || out["done"] != false {
			t.Errorf("%s on a new org: %d %v", id, status, out)
		}
	}
	if status, _ := step("verify_domain"); status != http.StatusNotFound {
		t.Errorf("another service's step: %d", status)
	}
	if status, _ := f.call(t, http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/onboarding/set_up_sso", f.service("user"), nil); status != http.StatusForbidden {
		t.Errorf("another service asking: %d", status)
	}
	owner, _ := f.owner(t, acme)
	if status, _ := f.call(t, http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/onboarding/set_up_sso", owner, nil); status != http.StatusForbidden {
		t.Errorf("a person asking: %d", status)
	}

	// One invite sent is enough, whatever becomes of it.
	if status, out := f.call(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/invites", owner, map[string]any{"email": "new@acme.com"}); status != http.StatusCreated {
		t.Fatalf("invite: %d %v", status, out)
	}
	if _, out := step("invite_teammates"); out["done"] != true {
		t.Errorf("after an invite: %v", out)
	}
	// Or a second member, however they came.
	f.users.add("one@globex.com", globex, "active", nil)
	globexStep := "/v1/internal/organizations/" + globex.String() + "/onboarding/invite_teammates"
	if _, out := f.call(t, http.MethodGet, globexStep, org, nil); out["done"] != false {
		t.Errorf("one member: %v", out)
	}
	f.users.add("two@globex.com", globex, "active", nil)
	if _, out := f.call(t, http.MethodGet, globexStep, org, nil); out["done"] != true {
		t.Errorf("two members: %v", out)
	}

	f.configure(acme)
	if _, out := step("set_up_sso"); out["done"] != true {
		t.Errorf("with a provider: %v", out)
	}
}
