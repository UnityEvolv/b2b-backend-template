package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if e, err := source.Entitlements(context.Background(), orgID); err != nil || e.Band != plan.Band("free") || len(e.Overrides) != 0 {
		t.Fatalf("before: %v %v", e, err)
	}
	do(t, h, http.MethodPut, "/v1/organizations/"+orgID+"/plan", operator, map[string]any{"plan": "team"}, "")
	e, err := source.Entitlements(context.Background(), orgID)
	if err != nil || e.Band != plan.Band("team") {
		t.Fatalf("after: %v %v", e, err)
	}
	// And the gate that reads it now refuses with a message naming the plan.
	if r, ok := plan.AsRefusal(e.CheckUsers(50)); !ok || r.Required != plan.Band("business") {
		t.Errorf("fifty-first user on team: %v", r)
	}
	if _, err := source.Entitlements(context.Background(), uuid.Must(uuid.NewV7()).String()); err != plan.ErrNoOrganization {
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

// withPlans is plan.Default replaced by what PLANS says, as main loads it,
// until the test ends.
func withPlans(t *testing.T, config string) {
	t.Helper()
	r := plan.New()
	r.SetBands(plan.DefaultBands())
	if err := r.Load(config); err != nil {
		t.Fatalf("PLANS: %v", err)
	}
	before := plan.Default
	plan.Default = r
	t.Cleanup(func() { plan.Default = before })
}

// productPlans is a product's PLANS: its own limit and feature, and a ladder
// with a band named and labelled its way.
const productPlans = `{
	"limits":[{"key":"projects","label":"projects"}],
	"features":[{"key":"exports","label":"scheduled exports","lost_code":"exports_stop","lost_message":"Scheduled exports stop."}],
	"bands":[
		{"name":"free","limits":{"users":10,"projects":3}},
		{"name":"team-50","label":"Team","limits":{"users":50,"projects":25},"features":["exports"]},
		{"name":"enterprise","contractual":true,"features":["exports","scim"]}]}`

// The catalogue is what the product registered through PLANS, labelled,
// to anyone signed in.
func TestPlanCatalogueIsTheRegistry(t *testing.T) {
	withPlans(t, productPlans)
	h, _, issuer := newAPI(t)

	if status, _ := get(t, h, "/v1/plans", ""); status != http.StatusUnauthorized {
		t.Errorf("signed out: %d", status)
	}
	status, out := get(t, h, "/v1/plans", tokenFor(t, issuer, testOrg))
	if status != http.StatusOK {
		t.Fatalf("catalogue: %d %v", status, out)
	}
	type band struct {
		label       string
		contractual bool
		users       float64
		projects    float64
		features    string
	}
	want := map[string]band{
		"free":       {"Free", false, 10, 3, ""},
		"team-50":    {"Team", false, 50, 25, "exports"},
		"enterprise": {"Enterprise", true, 0, 0, "exports,scim"},
	}
	bands := out["bands"].([]any)
	var names []string
	for _, x := range bands {
		b := x.(map[string]any)
		names = append(names, b["name"].(string))
		limits := b["limits"].(map[string]any)
		var features []string
		for _, f := range b["features"].([]any) {
			features = append(features, f.(string))
		}
		got := band{b["label"].(string), b["contractual"].(bool), limits["users"].(float64), limits["projects"].(float64), strings.Join(features, ",")}
		if got != want[b["name"].(string)] {
			t.Errorf("%s: %+v", b["name"], got)
		}
	}
	if strings.Join(names, ",") != "free,team-50,enterprise" {
		t.Errorf("ladder order: %v", names)
	}
	limitLabels, featureLabels := map[string]string{}, map[string]string{}
	for _, x := range out["limits"].([]any) {
		l := x.(map[string]any)
		limitLabels[l["key"].(string)] = l["label"].(string)
	}
	for _, x := range out["features"].([]any) {
		f := x.(map[string]any)
		featureLabels[f["key"].(string)] = f["label"].(string)
	}
	if limitLabels["users"] != "users" || limitLabels["projects"] != "projects" || len(limitLabels) != 2 {
		t.Errorf("limits: %v", limitLabels)
	}
	if featureLabels["exports"] != "scheduled exports" || featureLabels["scim"] != "SCIM provisioning" || featureLabels["audit_export"] == "" {
		t.Errorf("features: %v", featureLabels)
	}
}

// An org's own people, and platform operators, see its plan, what it
// allows, and its members against the cap, read now.
func TestOrganizationPlanIsReadNow(t *testing.T) {
	withPlans(t, productPlans)
	h, _, issuer := newAPI(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	member := tokenFor(t, issuer, orgID)
	path := "/v1/organizations/" + orgID + "/plan"
	deps.mu.Lock()
	deps.active[uuid.MustParse(orgID)] = 4
	deps.mu.Unlock()

	for _, token := range []string{member, operator} {
		status, out := get(t, h, path, token)
		limits, _ := out["limits"].(map[string]any)
		usage, _ := out["usage"].(map[string]any)
		if status != http.StatusOK || out["plan"] != "free" || out["label"] != "Free" || out["contractual"] != false ||
			limits["users"] != float64(10) || limits["projects"] != float64(3) || usage["users"] != float64(4) || len(out["features"].([]any)) != 0 {
			t.Errorf("free: %d %v", status, out)
		}
	}
	if status, _ := get(t, h, path, tokenFor(t, issuer, testOrg)); status != http.StatusForbidden {
		t.Errorf("another org's member: %d", status)
	}
	if status, _ := get(t, h, path, tokenForService(t, issuer, "billing")); status != http.StatusForbidden {
		t.Errorf("a service: %d", status)
	}
	if status, _ := get(t, h, "/v1/organizations/"+uuid.Must(uuid.NewV7()).String()+"/plan", operator); status != http.StatusNotFound {
		t.Errorf("no such org: %d", status)
	}

	// A change shows on the next read, and so does a new member.
	do(t, h, http.MethodPut, path, operator, map[string]any{"plan": "team-50"}, "")
	deps.mu.Lock()
	deps.active[uuid.MustParse(orgID)] = 5
	deps.mu.Unlock()
	status, out := get(t, h, path, member)
	usage, _ := out["usage"].(map[string]any)
	if status != http.StatusOK || out["plan"] != "team-50" || out["label"] != "Team" || out["limits"].(map[string]any)["projects"] != float64(25) ||
		usage["users"] != float64(5) || len(out["features"].([]any)) != 1 {
		t.Errorf("team-50: %d %v", status, out)
	}

	// Without the user service the plan still shows, without the usage.
	deps.mu.Lock()
	deps.countDown = true
	deps.mu.Unlock()
	status, out = get(t, h, path, member)
	if usage, _ := out["usage"].(map[string]any); status != http.StatusOK || out["plan"] != "team-50" || len(usage) != 0 {
		t.Errorf("user service down: %d %v", status, out)
	}
}
