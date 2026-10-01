package main

import (
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
)

// SCIM_GROUP_SYNC names a data owner; its URL is its own or its <NAME>_URL,
// and a name that is not an owner, or has no URL, stops the service.
func TestLocateGroupSync(t *testing.T) {
	r := dataowner.New()
	if err := r.Load(`[{"name":"projects"},{"name":"access-groups","url":"http://access-groups:8080"}]`); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PROJECTS_URL": "http://projects:8080"}
	lookup := func(k string) string { return env[k] }

	if u, err := locateGroupSync(r, lookup, ""); err != nil || u != "" {
		t.Errorf("unset: %q %v", u, err)
	}
	if u, err := locateGroupSync(r, lookup, "projects"); err != nil || u != "http://projects:8080" {
		t.Errorf("from PROJECTS_URL: %q %v", u, err)
	}
	if u, err := locateGroupSync(r, lookup, "access-groups"); err != nil || u != "http://access-groups:8080" {
		t.Errorf("from its entry: %q %v", u, err)
	}
	if _, err := locateGroupSync(r, lookup, "nobody"); err == nil || !strings.Contains(err.Error(), "DATA_OWNERS") {
		t.Errorf("not an owner: %v", err)
	}
	delete(env, "PROJECTS_URL")
	r2 := dataowner.New()
	r2.Load(`[{"name":"projects"}]`)
	if _, err := locateGroupSync(r2, lookup, "projects"); err == nil || !strings.Contains(err.Error(), "PROJECTS_URL") {
		t.Errorf("no URL: %v", err)
	}
}
