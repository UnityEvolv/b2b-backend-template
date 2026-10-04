package server_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
)

// stepAnswers is the other services, as the checklist asks them: done by
// step id, and the steps whose service is down.
type stepAnswers struct {
	mu    sync.Mutex
	done  map[string]bool
	down  map[string]bool
	asked []string
}

func (a *stepAnswers) Done(_ context.Context, s onboarding.Step, org uuid.UUID) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, s.Service+":"+s.ID+":"+org.String())
	if a.down[s.ID] {
		return false, errors.New("connection refused")
	}
	return a.done[s.ID], nil
}

// The checklist is derived from the data when it is read: this service's
// steps from its own row, the others from the service that knows, and a
// service that is down leaves its step unknown instead of failing the read.
func TestTheChecklistIsDerivedAtReadTime(t *testing.T) {
	h, cluster, issuer, srv, _ := newAPIAudited(t)
	steps := onboarding.New()
	steps.Register(onboarding.Step{ID: "create_project", Label: "Create your first project", Href: "/projects", Service: "projects", URL: "http://projects.test"})
	answers := &stepAnswers{done: map[string]bool{}, down: map[string]bool{}}
	srv.WithOnboarding(steps, answers)

	operator := platformToken(t, issuer)
	_, org := call(t, h, http.MethodPost, "/v1/organizations", operator, map[string]any{"name": "Initech", "time_zone": "UTC"})
	orgID := org["org_id"].(string)
	adminID, userID := uuid.NewString(), uuid.NewString()
	grants[orgID+"/"+adminID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	grants[orgID+"/"+userID] = authz.Grant{Role: authz.User}
	admin := tokenForMember(t, issuer, orgID, adminID)
	path := "/v1/organizations/" + orgID + "/onboarding"

	read := func() map[string]map[string]any {
		t.Helper()
		status, out := call(t, h, http.MethodGet, path, admin, nil)
		if status != http.StatusOK {
			t.Fatalf("checklist: %d %v", status, out)
		}
		got := map[string]map[string]any{}
		for i, raw := range out["steps"].([]any) {
			st := raw.(map[string]any)
			if want := steps.Steps()[i].ID; st["id"] != want {
				t.Fatalf("step %d is %v, want %s", i, st["id"], want)
			}
			got[st["id"].(string)] = st
		}
		got["*"] = out
		return got
	}
	got := read()
	for id, st := range got {
		if id != "*" && (st["done"] != false || st["unknown"] != false || st["dismissed"] != false) {
			t.Errorf("%s on a new org: %v", id, st)
		}
	}
	if got["choose_plan"]["href"] != "/billing" || got["choose_plan"]["app"] != "admin" || got["choose_plan"]["label"] == "" {
		t.Errorf("choose_plan: %v", got["choose_plan"])
	}

	// The data changes, the checklist follows: no flag was set anywhere.
	ctx := db.WithActor(context.Background(), db.SystemActor("organization"))
	if err := cluster.Tx(ctx, orgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE organizations SET domain = 'initech.com', domain_verified_at = now(), plan = 'team' WHERE org_id = $1`, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	answers.done["invite_teammates"], answers.done["create_project"] = true, true
	answers.down["set_up_sso"] = true
	got = read()
	for _, id := range []string{"verify_domain", "choose_plan", "invite_teammates", "create_project"} {
		if got[id]["done"] != true || got[id]["unknown"] != false {
			t.Errorf("%s: %v", id, got[id])
		}
	}
	if got["set_up_sso"]["unknown"] != true || got["set_up_sso"]["done"] != false || got["*"]["complete"] != false {
		t.Errorf("a service down: %v, complete %v", got["set_up_sso"], got["*"]["complete"])
	}
	// Each was asked of its own service, for this org, and this service's
	// own steps of nobody.
	for _, a := range answers.asked {
		if a != "identity:invite_teammates:"+orgID && a != "identity:set_up_sso:"+orgID && a != "projects:create_project:"+orgID {
			t.Errorf("asked %s", a)
		}
	}
	// Back on the lowest band, choose_plan is not done again.
	if err := cluster.Tx(ctx, orgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE organizations SET plan = 'free' WHERE org_id = $1`, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	answers.down["set_up_sso"] = false
	answers.done["set_up_sso"] = true
	if got := read(); got["choose_plan"]["done"] != false || got["*"]["complete"] != false {
		t.Errorf("back on free: %v", got["choose_plan"])
	}

	// Who may see it: the settings permission, so not a User, not another org.
	if status, _ := call(t, h, http.MethodGet, path, tokenForMember(t, issuer, orgID, userID), nil); status != http.StatusForbidden {
		t.Errorf("a User: %d", status)
	}
	if status, _ := call(t, h, http.MethodGet, path, tokenFor(t, issuer, uuid.NewString()), nil); status != http.StatusForbidden {
		t.Errorf("another org: %d", status)
	}
	if status, _ := call(t, h, http.MethodGet, path, "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token: %d", status)
	}
}

// Each step, and the whole checklist, is dismissed per org and brought
// back; a change is audited, a repeat is not.
func TestStepsAreDismissedPerOrg(t *testing.T) {
	h, _, issuer, srv, recorder := newAPIAudited(t)
	answers := &stepAnswers{done: map[string]bool{}, down: map[string]bool{}}
	srv.WithOnboarding(onboarding.New(), answers)
	operator := platformToken(t, issuer)
	orgs := []string{}
	for _, name := range []string{"Initech", "Initrode"} {
		_, org := call(t, h, http.MethodPost, "/v1/organizations", operator, map[string]any{"name": name, "time_zone": "UTC"})
		orgs = append(orgs, org["org_id"].(string))
	}
	ownerID, userID := uuid.NewString(), uuid.NewString()
	grants[orgs[0]+"/"+ownerID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	grants[orgs[0]+"/"+userID] = authz.Grant{Role: authz.User}
	owner := tokenForMember(t, issuer, orgs[0], ownerID)
	base := "/v1/organizations/" + orgs[0] + "/onboarding"

	if status, _ := call(t, h, http.MethodPost, base+"/steps/set_up_sso/dismissal", tokenForMember(t, issuer, orgs[0], userID), nil); status != http.StatusForbidden {
		t.Errorf("a User dismissing: %d", status)
	}
	if status, _ := call(t, h, http.MethodPost, base+"/steps/no_such_step/dismissal", owner, nil); status != http.StatusNotFound {
		t.Errorf("an unknown step: %d", status)
	}
	before := len(recorder.actions())
	for range 2 {
		if status, _ := call(t, h, http.MethodPost, base+"/steps/set_up_sso/dismissal", owner, nil); status != http.StatusNoContent {
			t.Fatalf("dismiss: %d", status)
		}
	}
	if status, _ := call(t, h, http.MethodPost, base+"/dismissal", owner, nil); status != http.StatusNoContent {
		t.Fatalf("dismiss all: %d", status)
	}
	_, out := call(t, h, http.MethodGet, base, owner, nil)
	if out["dismissed"] != true {
		t.Errorf("whole checklist: %v", out)
	}
	for _, raw := range out["steps"].([]any) {
		st := raw.(map[string]any)
		if (st["id"] == "set_up_sso") != (st["dismissed"] == true) {
			t.Errorf("%v", st)
		}
	}
	// The other org is untouched.
	_, other := call(t, h, http.MethodGet, "/v1/organizations/"+orgs[1]+"/onboarding", operator, nil)
	if other["dismissed"] != false || other["steps"].([]any)[2].(map[string]any)["dismissed"] != false {
		t.Errorf("another org: %v", other)
	}
	for _, path := range []string{base + "/steps/set_up_sso/dismissal", base + "/dismissal"} {
		if status, _ := call(t, h, http.MethodDelete, path, owner, nil); status != http.StatusNoContent {
			t.Fatalf("restore %s: %d", path, status)
		}
	}
	_, out = call(t, h, http.MethodGet, base, owner, nil)
	if out["dismissed"] != false || out["steps"].([]any)[2].(map[string]any)["dismissed"] != false {
		t.Errorf("restored: %v", out)
	}
	got := recorder.actions()[before:]
	want := []string{"onboarding.step_dismissed", "onboarding.dismissed", "onboarding.step_restored", "onboarding.restored"}
	if len(got) != len(want) {
		t.Fatalf("audited %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audited %v, want %v", got, want)
		}
	}
}
