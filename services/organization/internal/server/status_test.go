package server_test

import (
	"net/http"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// The org detail story: an operator suspends and reactivates an org, with
// the reason audited; members cannot; the platform itself cannot be
// suspended; the list filters by status; and an operator reading the org
// leaves a support entry on its log while a member reading it does not.
func TestSuspensionAndSupportViews(t *testing.T) {
	h, _, issuer, _, recorder := newAPIAudited(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	member := tokenFor(t, issuer, orgID)
	path := "/v1/organizations/" + orgID + "/status"

	if status, _ := do(t, h, http.MethodPut, path, member, map[string]any{"status": "suspended", "reason": "x"}, ""); status != http.StatusForbidden {
		t.Errorf("member suspending: %d", status)
	}
	if status, _ := do(t, h, http.MethodPut, path, operator, map[string]any{"status": "suspended"}, ""); status != http.StatusBadRequest {
		t.Errorf("suspending without a reason: %d", status)
	}
	if status, _ := do(t, h, http.MethodPut, "/v1/organizations/"+auth.PlatformOrg+"/status", operator, map[string]any{"status": "suspended", "reason": "x"}, ""); status != http.StatusForbidden {
		t.Errorf("suspending the platform: %d", status)
	}
	status, out := do(t, h, http.MethodPut, path, operator, map[string]any{"status": "suspended", "reason": "Unpaid invoice"}, "")
	if status != http.StatusOK || out["status"] != "suspended" || out["suspension_reason"] != "Unpaid invoice" || out["suspended_at"] == nil {
		t.Fatalf("suspend: %d %v", status, out)
	}
	if out["user_cap"] != float64(10) {
		t.Errorf("free plan cap: %v", out["user_cap"])
	}
	if status, out := get(t, h, "/v1/organizations?status=suspended", operator); status != http.StatusOK || len(out["organizations"].([]any)) != 1 {
		t.Errorf("filter suspended: %d %v", status, out)
	}
	if status, out := get(t, h, "/v1/organizations?status=active", operator); status != http.StatusOK || len(out["organizations"].([]any)) != 0 {
		t.Errorf("filter active: %d %v", status, out)
	}
	status, out = do(t, h, http.MethodPut, path, operator, map[string]any{"status": "active"}, "")
	if status != http.StatusOK || out["status"] != "active" || out["suspended_at"] != nil || out["suspension_reason"] != nil {
		t.Fatalf("reactivate: %d %v", status, out)
	}

	get(t, h, "/v1/organizations/"+orgID, member)
	get(t, h, "/v1/organizations/"+orgID, operator)
	counts := map[string]int{}
	for _, ev := range recorder.events {
		counts[ev.Action]++
		if ev.Action == "organization.suspended" && ev.Details["reason"] != "Unpaid invoice" {
			t.Errorf("suspension audit: %v", ev.Details)
		}
	}
	if counts["organization.suspended"] != 1 || counts["organization.reactivated"] != 1 || counts["support.viewed"] != 1 {
		t.Errorf("audited: %v", counts)
	}
}
