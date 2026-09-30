package server_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

func (f *fixture) cancels() []string {
	f.pay.mu.Lock()
	defer f.pay.mu.Unlock()
	var out []string
	for _, c := range f.pay.calls {
		if strings.HasPrefix(c, "cancel:") {
			out = append(out, c)
		}
	}
	return out
}

func internal(org uuid.UUID, rest string) string {
	return "/v1/internal/organizations/" + org.String() + rest
}

// Closing an org cancels its subscription at the provider now and records
// the account as cancelled on free; a second call does nothing more.
func TestClosingCancelsTheSubscription(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	f.card(t, owner)
	if code, out := f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team"}); code != http.StatusOK {
		t.Fatalf("subscribe: %d %v", code, out)
	}
	org := f.token(t, auth.Caller{Service: "organization"})

	for i := range 2 {
		if code, out := f.do(t, http.MethodPost, internal(f.org, "/close"), org, nil); code != http.StatusNoContent {
			t.Fatalf("close %d: %d %v", i, code, out)
		}
	}
	if got := f.cancels(); len(got) != 1 || !strings.HasPrefix(got[0], "cancel:sub_") {
		t.Errorf("provider cancels: %v", got)
	}
	_, part := f.do(t, http.MethodGet, internal(f.org, "/data"), org, nil)
	account := part["data"].(map[string]any)["account"].(map[string]any)
	if account["state"] != "cancelled" || account["band"] != "free" {
		t.Errorf("account after closing: %v", account)
	}

	// An org that never subscribed: nothing to cancel.
	if code, _ := f.do(t, http.MethodPost, internal(uuid.Must(uuid.NewV7()), "/close"), org, nil); code != http.StatusNoContent {
		t.Errorf("no account: %d", code)
	}
	if got := f.cancels(); len(got) != 1 {
		t.Errorf("cancels after a no-op: %v", got)
	}
}

// The export is the account without provider references; purge removes it,
// answers zero twice, and leaves another org's account alone.
func TestExportAndPurgeAnOrg(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	f.card(t, owner)
	other := uuid.Must(uuid.NewV7())
	// Billing is asked about another org: it has an account too.
	if code, _ := f.do(t, http.MethodPost, internal(other, "/members-changed"), f.user, map[string]any{"members": 1}); code != http.StatusNoContent {
		t.Fatalf("other org: %d", code)
	}
	org := f.token(t, auth.Caller{Service: "organization"})

	code, part := f.do(t, http.MethodGet, internal(f.org, "/data"), org, nil)
	if code != http.StatusOK || part["service"] != "billing" {
		t.Fatalf("export: %d %v", code, part)
	}
	account := part["data"].(map[string]any)["account"].(map[string]any)
	if account["card_last4"] != "4242" || account["card_brand"] != "visa" || account["band"] != "free" {
		t.Errorf("account: %v", account)
	}
	for _, secret := range []string{"customer_ref", "subscription_ref", "schedule_ref", "notices"} {
		if _, ok := account[secret]; ok {
			t.Errorf("export carries %s", secret)
		}
	}

	for i := range 2 {
		code, out := f.do(t, http.MethodDelete, internal(f.org, "/data"), org, nil)
		if code != http.StatusOK || out["remaining"] != float64(0) {
			t.Fatalf("purge %d: %d %v", i, code, out)
		}
	}
	if _, part := f.do(t, http.MethodGet, internal(f.org, "/data"), org, nil); part["data"].(map[string]any)["account"] != nil {
		t.Errorf("purged org still has an account: %v", part)
	}
	if _, part := f.do(t, http.MethodGet, internal(other, "/data"), org, nil); part["data"].(map[string]any)["account"] == nil {
		t.Errorf("the other org's account went: %v", part)
	}
}

func TestPersonalExportIsEmpty(t *testing.T) {
	f := newAPI(t)
	org := f.token(t, auth.Caller{Service: "organization"})
	code, part := f.do(t, http.MethodGet, "/v1/internal/users/"+uuid.NewString()+"/data?membership="+f.org.String()+":"+uuid.NewString(), org, nil)
	if code != http.StatusOK || part["service"] != "billing" || part["data"].(map[string]any)["note"] == nil {
		t.Errorf("personal export: %d %v", code, part)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/internal/users/"+uuid.NewString()+"/data?membership=bad", org, nil); code != http.StatusBadRequest {
		t.Errorf("a bad membership: %d", code)
	}
}

func TestDataEndpointsAreTheOrganizationServicesOnly(t *testing.T) {
	f := newAPI(t)
	owner := f.member(t, authz.Owner)
	f.card(t, owner)
	f.do(t, http.MethodPut, f.path("/billing/band"), owner, map[string]any{"band": "team"})
	for _, token := range []string{f.user, owner} {
		for _, c := range [][2]string{
			{http.MethodGet, internal(f.org, "/data")},
			{http.MethodDelete, internal(f.org, "/data")},
			{http.MethodGet, "/v1/internal/users/" + uuid.NewString() + "/data"},
			{http.MethodPost, internal(f.org, "/close")},
		} {
			if code, _ := f.do(t, c[0], c[1], token, nil); code != http.StatusForbidden {
				t.Errorf("%s %s: %d", c[0], c[1], code)
			}
		}
	}
	if got := f.cancels(); len(got) != 0 {
		t.Errorf("cancelled by a refused call: %v", got)
	}
}
