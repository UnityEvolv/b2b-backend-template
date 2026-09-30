package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
)

func TestPlanChangeIsAnOperatorsAuditedAction(t *testing.T) {
	h, _, issuer, _, recorder := newAPIAudited(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	member := tokenFor(t, issuer, orgID)
	path := "/v1/organizations/" + orgID + "/plan"

	// A new org is on free, and a member cannot move it.
	if status, out := do(t, h, http.MethodPut, path, member, map[string]any{"plan": "enterprise"}, ""); status != http.StatusForbidden || out["code"] != httpx.CodeForbidden {
		t.Errorf("member changing the plan: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPut, path, tokenForService(t, issuer, "billing"), map[string]any{"plan": "team"}, ""); status != http.StatusForbidden {
		t.Errorf("service changing the plan: %d %v", status, out)
	}
	// The operator can; the org's members see it at once.
	if status, out := do(t, h, http.MethodPut, path, operator, map[string]any{"plan": "business"}, ""); status != http.StatusOK || out["plan"] != "business" {
		t.Fatalf("operator changing the plan: %d %v", status, out)
	}
	if status, out := get(t, h, "/v1/organizations/"+orgID, member); status != http.StatusOK || out["plan"] != "business" {
		t.Errorf("member reading the new plan: %d %v", status, out)
	}
	// Same plan again is a no-op, not a second audit entry; an unknown plan is refused.
	if status, out := do(t, h, http.MethodPut, path, operator, map[string]any{"plan": "business"}, ""); status != http.StatusOK {
		t.Errorf("same plan: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPut, path, operator, map[string]any{"plan": "gold"}, ""); status != http.StatusBadRequest || out["code"] != httpx.CodeInvalidRequest {
		t.Errorf("unknown plan: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPut, "/v1/organizations/"+uuid.Must(uuid.NewV7()).String()+"/plan", operator, map[string]any{"plan": "free"}, ""); status != http.StatusNotFound {
		t.Errorf("no such org: %d %v", status, out)
	}

	changes := 0
	for _, ev := range recorder.events {
		if ev.Action == "organization.plan.changed" {
			changes++
			if ev.Details["from"] != "free" || ev.Details["to"] != "business" || ev.Details["downgrade"] != false {
				t.Errorf("audit details: %v", ev.Details)
			}
		}
	}
	if changes != 1 {
		t.Errorf("plan change audited %d times", changes)
	}
}

func TestPlanChangePreviewIsTheDowngradeChecklist(t *testing.T) {
	h, _, issuer := newAPI(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	do(t, h, http.MethodPut, "/v1/organizations/"+orgID+"/plan", operator, map[string]any{"plan": "business"}, "")
	member := tokenFor(t, issuer, orgID)

	status, out := get(t, h, "/v1/organizations/"+orgID+"/plan-change?plan=free", member)
	if status != http.StatusOK || out["from"] != "business" || out["to"] != "free" || out["downgrade"] != true {
		t.Fatalf("preview: %d %v", status, out)
	}
	codes := map[string]bool{}
	for _, c := range out["consequences"].([]any) {
		codes[c.(map[string]any)["code"].(string)] = true
	}
	for _, want := range []string{"users_over_cap_kept"} {
		if !codes[want] {
			t.Errorf("checklist lacks %s: %v", want, codes)
		}
	}
	// An upgrade closes nothing; an unknown plan is refused; another org's member is not shown it.
	if status, out := get(t, h, "/v1/organizations/"+orgID+"/plan-change?plan=enterprise", member); status != http.StatusOK || out["downgrade"] != false || len(out["consequences"].([]any)) != 0 {
		t.Errorf("upgrade preview: %d %v", status, out)
	}
	if status, out := get(t, h, "/v1/organizations/"+orgID+"/plan-change?plan=gold", member); status != http.StatusBadRequest {
		t.Errorf("unknown plan: %d %v", status, out)
	}
	if status, out := get(t, h, "/v1/organizations/"+orgID+"/plan-change?plan=free", tokenFor(t, issuer, testOrg)); status != http.StatusForbidden {
		t.Errorf("another org: %d %v", status, out)
	}
}

// A service reads the plan and its limits at the moment of an action,
// through pkg/plan's client, and gets the platform's table for the band.
func TestServicesReadThePlanAtTheMomentOfTheAction(t *testing.T) {
	h, _, issuer := newAPI(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	path := "/v1/internal/organizations/" + orgID + "/plan"

	status, out := get(t, h, path, tokenForService(t, issuer, "user"))
	if status != http.StatusOK || out["plan"] != "free" || out["contractual"] != false || out["limits"].(map[string]any)["users"] != float64(10) {
		t.Fatalf("free limits: %d %v", status, out)
	}
	if features := out["features"].([]any); len(features) != 0 {
		t.Errorf("free has gated features: %v", features)
	}
	// People, even platform operators, use the org endpoint instead.
	for _, token := range []string{tokenFor(t, issuer, orgID), operator} {
		if status, _ := get(t, h, path, token); status != http.StatusForbidden {
			t.Errorf("a person reading the internal plan endpoint: %d", status)
		}
	}

	// Through the client another service would use, before and after a change.
	srv := httptest.NewServer(h)
	defer srv.Close()
	source := plan.Client(srv.URL, auth.StaticToken(tokenForService(t, issuer, "user")), nil)
	if band, err := source.Band(context.Background(), orgID); err != nil || band != plan.Band("free") {
		t.Fatalf("before: %v %v", band, err)
	}
	do(t, h, http.MethodPut, "/v1/organizations/"+orgID+"/plan", operator, map[string]any{"plan": "team"}, "")
	band, err := source.Band(context.Background(), orgID)
	if err != nil || band != plan.Band("team") {
		t.Fatalf("after: %v %v", band, err)
	}
	// And the gate that reads it now refuses with a message naming the plan.
	if r, ok := plan.AsRefusal(plan.CheckUsers(band, 50)); !ok || r.Required != plan.Band("business") {
		t.Errorf("fifty-first user on team: %v", r)
	}
	if _, err := source.Band(context.Background(), uuid.Must(uuid.NewV7()).String()); err != plan.ErrNoOrganization {
		t.Errorf("unknown org: %v", err)
	}
}

// Billing moves the plan through its own endpoint, with a reason; nobody
// else may, and an enterprise org is left to a platform operator.
func TestBillingSetsThePlan(t *testing.T) {
	h, _, issuer := newAPI(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	path := "/v1/internal/organizations/" + orgID + "/plan"
	billing := tokenForService(t, issuer, "billing")

	status, out := do(t, h, http.MethodPut, path, billing, map[string]any{"plan": "business", "reason": "upgrade"}, "")
	if status != http.StatusOK || out["plan"] != "business" {
		t.Fatalf("billing: %d %v", status, out)
	}
	if status, _ := do(t, h, http.MethodPut, path, tokenForService(t, issuer, "user"), map[string]any{"plan": "free", "reason": "downgrade"}, ""); status != http.StatusForbidden {
		t.Errorf("another service: %d", status)
	}
	do(t, h, http.MethodPut, "/v1/organizations/"+orgID+"/plan", operator, map[string]any{"plan": "enterprise"}, "")
	if status, _ := do(t, h, http.MethodPut, path, billing, map[string]any{"plan": "free", "reason": "payment_failure"}, ""); status != http.StatusConflict {
		t.Errorf("billing moving an enterprise org: %d", status)
	}
}
