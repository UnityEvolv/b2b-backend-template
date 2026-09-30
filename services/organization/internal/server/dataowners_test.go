package server_test

import (
	"archive/zip"
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/server"
)

// ownedOrg is an org with an Owner who has an address, on srv.
type ownedOrg struct {
	id, path, token string
}

func newOwnedOrg(t *testing.T, h http.Handler, issuer interface {
	Issue(auth.Caller, time.Duration) (string, error)
}, operator string, fakes *offFakes, name string) ownedOrg {
	t.Helper()
	orgID := create(t, h, operator, map[string]any{"name": name, "time_zone": "UTC"})["org_id"].(string)
	owner, user := uuid.NewString(), uuid.New()
	grants[orgID+"/"+owner] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	fakes.mu.Lock()
	fakes.emails[user] = "owner@" + strings.ToLower(name) + ".test"
	fakes.mu.Unlock()
	token, err := issuer.Issue(auth.Caller{UserID: user.String(), OrgID: orgID, MembershipID: owner}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ownedOrg{id: orgID, path: "/v1/organizations/" + orgID, token: token}
}

func (f *offFakes) archive(t *testing.T) map[string]bool {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	names := map[string]bool{}
	for k, v := range f.objects {
		if !strings.Contains(k, "/data-export/") {
			continue
		}
		z, err := zip.NewReader(bytes.NewReader(v), int64(len(v)))
		if err != nil {
			t.Fatalf("archive: %v", err)
		}
		for _, file := range z.File {
			names[file.Name] = true
		}
	}
	return names
}

// With only the template's data owners registered, an export
// gathers a part from each and a purge empties each, audit last, and both
// complete. Nothing in the organization service names an owner.
func TestOffboardingWithTheTemplatesOwnersOnly(t *testing.T) {
	h, _, issuer, srv, _ := newAPIAudited(t)
	fakes := newOffFakes()
	clock := &clockT{t: time.Now()}
	owners := dataowner.New()
	srv.WithOffboarding(server.Offboarding{Platform: fakes, Data: fakes, Files: fakes, Owners: owners, Now: clock.now})
	operator := platformToken(t, issuer)
	org := newOwnedOrg(t, h, issuer, operator, fakes, "Hooli")

	if status, _ := do(t, h, http.MethodPost, org.path+"/exports", org.token, nil, "k1"); status != http.StatusAccepted {
		t.Fatalf("export: %d", status)
	}
	if err := srv.RunExports(t.Context()); err != nil {
		t.Fatalf("export pass: %v", err)
	}
	names := fakes.archive(t)
	want := []string{"README.md", "organization/data.json"}
	for _, o := range owners.Exporters() {
		want = append(want, o.Name+"/data.json")
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("archive without %s: %v", w, names)
		}
	}
	if len(names) != len(want) {
		t.Errorf("archive has more than the template's owners: %v", names)
	}

	if status, _ := do(t, h, http.MethodPost, org.path+"/close", org.token, map[string]any{"confirm_name": "Hooli"}, ""); status != http.StatusOK {
		t.Fatalf("close: %d", status)
	}
	clock.add(31 * 24 * time.Hour)
	if err := srv.RunPurges(t.Context()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	wantOrder := []string{"notification", "billing", "authorization", "identity", "user", "audit"}
	if !slices.Equal(fakes.purgeLog, wantOrder) {
		t.Errorf("purged %v, want %v", fakes.purgeLog, wantOrder)
	}
	if status, _ := get(t, h, org.path, operator); status != http.StatusNotFound {
		t.Errorf("a purged org is still there: %d", status)
	}
}

// A data owner whose call fails blocks the export and the purge,
// and is named: on the export (blocked_by), in the pass's error and, for a
// purge, in the org's audit log. Nothing is skipped; once it answers,
// both complete.
func TestAFailingDataOwnerBlocksAndIsReported(t *testing.T) {
	h, _, issuer, srv, recorder := newAPIAudited(t)
	fakes := newOffFakes()
	clock := &clockT{t: time.Now()}
	srv.WithOffboarding(server.Offboarding{Platform: fakes, Data: fakes, Files: fakes, Owners: offOwners(), Now: clock.now})
	operator := platformToken(t, issuer)
	org := newOwnedOrg(t, h, issuer, operator, fakes, "Pied")
	fakes.failing = "projects"

	status, e := do(t, h, http.MethodPost, org.path+"/exports", org.token, nil, "k1")
	if status != http.StatusAccepted {
		t.Fatalf("export: %d", status)
	}
	exportOf := func() map[string]any {
		_, list := get(t, h, org.path+"/exports", org.token)
		for _, x := range list["exports"].([]any) {
			if x.(map[string]any)["id"] == e["id"] {
				return x.(map[string]any)
			}
		}
		t.Fatalf("export %v not listed", e["id"])
		return nil
	}
	err := srv.RunExports(t.Context())
	if err == nil || !strings.Contains(err.Error(), "projects") {
		t.Errorf("the pass does not name the failing owner: %v", err)
	}
	if got := exportOf(); got["status"] != "pending" || got["blocked_by"] != "projects" || got["download_url"] != nil {
		t.Errorf("a blocked export: %v", got)
	}
	_ = srv.RunExports(t.Context())
	_ = srv.RunExports(t.Context())
	if got := exportOf(); got["status"] != "failed" || got["blocked_by"] != "projects" {
		t.Errorf("after three attempts: %v", got)
	}
	if len(fakes.archive(t)) != 0 {
		t.Error("an archive was made without the failing owner's part")
	}

	if status, _ := do(t, h, http.MethodPost, org.path+"/close", org.token, map[string]any{"confirm_name": "Pied"}, ""); status != http.StatusOK {
		t.Fatalf("close: %d", status)
	}
	clock.add(31 * 24 * time.Hour)
	err = srv.RunPurges(t.Context())
	if err == nil || !strings.Contains(err.Error(), "projects") {
		t.Errorf("the purge does not name the failing owner: %v", err)
	}
	if status, _ := get(t, h, org.path, operator); status != http.StatusOK {
		t.Errorf("the org went although projects still holds it: %d", status)
	}
	if fakes.purged["audit"] != 0 {
		t.Error("audit was purged although an owner before it failed")
	}
	if !recorder.has("organization.purge_blocked") {
		t.Error("the blocked purge is not audited")
	}
	fakes.failing = ""
	if err := srv.RunPurges(t.Context()); err != nil {
		t.Fatalf("purge once projects answers: %v", err)
	}
	if fakes.purged["projects"] != 1 {
		t.Errorf("purged %v", fakes.purged)
	}
	if status, _ := get(t, h, org.path, operator); status != http.StatusNotFound {
		t.Errorf("a purged org is still there: %d", status)
	}
}
