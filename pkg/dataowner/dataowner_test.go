package dataowner_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
)

func names(owners []dataowner.Owner) []string {
	var out []string
	for _, o := range owners {
		out = append(out, o.Name)
	}
	return out
}

// The template's owners: all six export and purge, audit last; only
// notification erases and only identity decrypts.
func TestTheTemplatesOwners(t *testing.T) {
	r := dataowner.New()
	if got := names(r.Exporters()); !slices.Equal(got, []string{"notification", "billing", "authorization", "identity", "user", "audit"}) {
		t.Errorf("exporters %v", got)
	}
	if got := names(r.Erasers()); !slices.Equal(got, []string{"notification"}) {
		t.Errorf("erasers %v", got)
	}
	if got := r.Decrypting(); !slices.Equal(got, []string{"identity"}) {
		t.Errorf("decrypting %v", got)
	}
}

// A product's owner, from configuration: purged before audit, erasing,
// decrypting, and known; one with no capability is only known.
func TestAProductsOwners(t *testing.T) {
	r := dataowner.New()
	err := r.Load(`[{"name":"projects","url":"http://projects:8080","export":true,"purge":true,"erase":true,"decrypt":true},{"name":"reports"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(r.Purgers()); !slices.Equal(got, []string{"notification", "billing", "authorization", "identity", "user", "projects", "audit"}) {
		t.Errorf("purge order %v", got)
	}
	if got := names(r.Erasers()); !slices.Equal(got, []string{"notification", "projects"}) {
		t.Errorf("erasers %v", got)
	}
	if got := r.Decrypting(); !slices.Equal(got, []string{"identity", "projects"}) {
		t.Errorf("decrypting %v", got)
	}
	if !r.Known("reports") || slices.Contains(names(r.Exporters()), "reports") || r.Known("documents") {
		t.Error("a caller-only entry")
	}
	m := r.Manifest()
	if len(m.Owners) != 8 || m.Owners[6].URL != "" || !slices.Equal(m.Decrypting, []string{"identity", "projects"}) {
		t.Errorf("manifest %+v", m)
	}
	for _, bad := range []string{`[{"name":"Projects"}]`, `[{"name":""}]`, `[{"name":"x","exports":true}]`, `{`} {
		if _, err := dataowner.Parse(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Locating: an owner's own URL, else <NAME>_URL; a missing one is named
// and fails start, and owners not needed are not asked for.
func TestLocate(t *testing.T) {
	r := dataowner.New()
	r.Register(dataowner.Owner{Name: "project-files", Export: true, Purge: true})
	r.Register(dataowner.Owner{Name: "reports"})
	env := map[string]string{"NOTIFICATION_URL": "http://notification:8080", "BILLING_URL": "http://billing:8080",
		"AUTHORIZATION_URL": "http://authorization:8080", "IDENTITY_URL": "http://identity:8080", "USER_URL": "http://user:8080"}
	lookup := func(k string) string { return env[k] }
	err := r.Locate(lookup, dataowner.Owner.HoldsOrgData)
	if err == nil || !strings.Contains(err.Error(), "AUDIT_URL") || !strings.Contains(err.Error(), "PROJECT_FILES_URL") || strings.Contains(err.Error(), "REPORTS_URL") {
		t.Fatalf("missing settings: %v", err)
	}
	env["AUDIT_URL"], env["PROJECT_FILES_URL"] = "http://audit:8080", "http://files:8080"
	if err := r.Locate(lookup, dataowner.Owner.HoldsOrgData); err != nil {
		t.Fatal(err)
	}
	for _, o := range r.Purgers() {
		if o.URL == "" {
			t.Errorf("%s not located", o.Name)
		}
	}
}
