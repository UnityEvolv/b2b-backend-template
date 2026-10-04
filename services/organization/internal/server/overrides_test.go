package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
)

// A platform operator sets an enterprise deal's exceptions to the band: a
// higher seat cap and a feature the band lacks. Every service's gate reads
// them through pkg/plan's client with the band; the org's plan page shows
// the effective values and marks the overridden ones with their end; every
// change is audited on the org; and one past its end simply stops applying.
func TestPlanOverridesApplyUntilTheyEnd(t *testing.T) {
	h, cluster, issuer, _, recorder := newAPIAudited(t)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	member := tokenFor(t, issuer, orgID)
	overrides := "/v1/organizations/" + orgID + "/plan-overrides"
	srv := httptest.NewServer(h)
	defer srv.Close()
	source := plan.Client(srv.URL, auth.StaticToken(tokenForService(t, issuer, "user")), nil)
	ctx := context.Background()

	// Only a platform operator sets, lists or removes one.
	for _, token := range []string{member, tokenForService(t, issuer, "billing")} {
		if status, _ := do(t, h, http.MethodPut, overrides+"/limit/users", token, map[string]any{"cap": 75}, ""); status != http.StatusForbidden {
			t.Errorf("set by a non-operator: %d", status)
		}
		if status, _ := get(t, h, overrides, token); status != http.StatusForbidden {
			t.Errorf("listed by a non-operator: %d", status)
		}
	}
	// Only a registered key, with the value its kind takes, and an end ahead.
	for _, bad := range []struct {
		path string
		body map[string]any
	}{
		{"/limit/seats", map[string]any{"cap": 75}},
		{"/feature/teleport", map[string]any{"allowed": true}},
		{"/limit/users", map[string]any{"allowed": true}},
		{"/feature/scim", map[string]any{"cap": 1}},
		{"/limit/users", map[string]any{"cap": -1}},
		{"/limit/users", map[string]any{"cap": 75, "ends_at": time.Now().Add(-time.Hour).Format(time.RFC3339)}},
	} {
		if status, out := do(t, h, http.MethodPut, overrides+bad.path, operator, bad.body, ""); status != http.StatusBadRequest {
			t.Errorf("%s %v: %d %v", bad.path, bad.body, status, out)
		}
	}
	if status, _ := do(t, h, http.MethodPut, "/v1/organizations/"+uuid.Must(uuid.NewV7()).String()+"/plan-overrides/limit/users", operator, map[string]any{"cap": 75}, ""); status != http.StatusNotFound {
		t.Errorf("no such org: %d", status)
	}

	// Free caps users at 10 and has no SCIM. The deal: 75 seats until the
	// end of the trial, and SCIM with no end.
	ends := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	status, out := do(t, h, http.MethodPut, overrides+"/limit/users", operator, map[string]any{"cap": 75, "ends_at": ends.Format(time.RFC3339)}, "")
	if status != http.StatusOK || out["kind"] != "limit" || out["key"] != "users" || out["cap"] != float64(75) || out["in_force"] != true || out["ends_at"] != ends.Format(time.RFC3339) {
		t.Fatalf("set the cap: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPut, overrides+"/feature/scim", operator, map[string]any{"allowed": true}, ""); status != http.StatusOK || out["allowed"] != true {
		t.Fatalf("grant SCIM: %d %v", status, out)
	}

	e, err := source.Entitlements(ctx, orgID)
	if err != nil || e.Band != "free" || len(e.Overrides) != 2 {
		t.Fatalf("entitlements: %+v %v", e, err)
	}
	if err := e.CheckUsers(10); err != nil {
		t.Errorf("eleventh user under a 75-seat deal: %v", err)
	}
	if r, ok := plan.AsRefusal(e.CheckUsers(75)); !ok || r.Plan != "free" || r.Limit != "users" {
		t.Errorf("seventy-sixth user: %v", r)
	}
	if err := e.CheckFeature(plan.SCIM); err != nil {
		t.Errorf("SCIM granted: %v", err)
	}
	if err := e.CheckFeature(plan.AuditExport); err == nil {
		t.Error("audit export, which the deal does not grant")
	}

	// The org's own page shows the effective values and marks the overrides.
	status, out = get(t, h, "/v1/organizations/"+orgID+"/plan", member)
	if status != http.StatusOK || out["plan"] != "free" || out["limits"].(map[string]any)["users"] != float64(75) {
		t.Fatalf("plan page: %d %v", status, out)
	}
	if f := out["features"].([]any); len(f) != 1 || f[0] != "scim" {
		t.Errorf("plan page features: %v", f)
	}
	marked := map[string]map[string]any{}
	for _, x := range out["overrides"].([]any) {
		o := x.(map[string]any)
		marked[o["kind"].(string)+"/"+o["key"].(string)] = o
	}
	if o := marked["limit/users"]; o == nil || o["cap"] != float64(75) || o["ends_at"] != ends.Format(time.RFC3339) {
		t.Errorf("users override on the page: %v", marked)
	}
	if o := marked["feature/scim"]; o == nil || o["allowed"] != true || o["ends_at"] != nil {
		t.Errorf("SCIM override on the page: %v", marked)
	}

	// The deal ends: nothing runs, and the next check is the band's again.
	err = cluster.Tx(db.WithActor(ctx, db.SystemActor("organization")), orgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE plan_overrides SET ends_at = now() - interval '1 minute' WHERE org_id = $1 AND key = 'users'`, orgID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err = source.Entitlements(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := plan.AsRefusal(e.CheckUsers(10)); !ok || r.Required != "team" {
		t.Errorf("eleventh user after the deal ended: %v", r)
	}
	status, out = get(t, h, "/v1/organizations/"+orgID+"/plan", member)
	if status != http.StatusOK || out["limits"].(map[string]any)["users"] != float64(10) || len(out["overrides"].([]any)) != 1 {
		t.Errorf("plan page after the end: %d %v", status, out)
	}
	// The console still lists it, as ended.
	status, out = get(t, h, overrides, operator)
	if status != http.StatusOK || len(out["overrides"].([]any)) != 2 {
		t.Fatalf("console list: %d %v", status, out)
	}
	for _, x := range out["overrides"].([]any) {
		o := x.(map[string]any)
		if want := o["key"] != "users"; o["in_force"] != want {
			t.Errorf("in force: %v", o)
		}
	}

	// A feature can be taken away as well as granted, and removing an
	// override puts the band back.
	withEnterprise := func() {
		do(t, h, http.MethodPut, "/v1/organizations/"+orgID+"/plan", operator, map[string]any{"plan": "enterprise"}, "")
	}
	withEnterprise()
	do(t, h, http.MethodPut, overrides+"/feature/audit_export", operator, map[string]any{"allowed": false}, "")
	if e, _ = source.Entitlements(ctx, orgID); e.CheckFeature(plan.AuditExport) == nil {
		t.Error("audit export taken away, but allowed")
	}
	if status, _ := do(t, h, http.MethodDelete, overrides+"/feature/audit_export", operator, nil, ""); status != http.StatusNoContent {
		t.Errorf("remove: %d", status)
	}
	if e, _ = source.Entitlements(ctx, orgID); e.CheckFeature(plan.AuditExport) != nil {
		t.Error("audit export back with the band, but refused")
	}
	if status, out := do(t, h, http.MethodDelete, overrides+"/feature/audit_export", operator, nil, ""); status != http.StatusNotFound {
		t.Errorf("remove again: %d %v", status, out)
	}

	// Every change is on the org's own audit log, with the values.
	var set, removed int
	for _, ev := range recorder.events {
		if ev.OrgID != orgID {
			continue
		}
		switch ev.Action {
		case "organization.plan.override_set":
			set++
			if ev.Details["key"] == "users" && (ev.Details["cap"] != 75 || ev.Details["ends_at"] != ends.Format(time.RFC3339)) {
				t.Errorf("set details: %v", ev.Details)
			}
		case "organization.plan.override_removed":
			removed++
			if prev, _ := ev.Details["previous"].(map[string]any); prev["key"] != "audit_export" || prev["allowed"] != false {
				t.Errorf("removed details: %v", ev.Details)
			}
		}
	}
	if set != 3 || removed != 1 {
		t.Errorf("audited %d sets and %d removals", set, removed)
	}
}
