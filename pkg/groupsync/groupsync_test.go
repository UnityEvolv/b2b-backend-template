package groupsync_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/groupsync"
)

// The client posts the whole group to the product's endpoint with the
// user service's token, and reads who was added and removed.
func TestSync(t *testing.T) {
	org, group, mbr := uuid.New(), uuid.New(), uuid.New()
	var got groupsync.Request
	product := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != groupsync.Path(org, group) || r.Header.Get("Authorization") != "Bearer svc-token" {
			http.Error(w, "wrong call", http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(groupsync.Result{Added: []uuid.UUID{mbr}, Removed: []uuid.UUID{}})
	}))
	defer product.Close()

	c := groupsync.NewClient("projects", product.URL+"/", auth.StaticToken("svc-token"), nil)
	res, err := c.Sync(context.Background(), groupsync.Request{OrgID: org, GroupID: group, DisplayName: "Design",
		Members: []groupsync.Member{{MembershipID: mbr, UserID: uuid.New()}}, Change: groupsync.ChangeDirectory, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Added[0] != mbr {
		t.Errorf("result: %+v", res)
	}
	if got.OrgID != org || got.GroupID != group || got.DisplayName != "Design" || got.Change != "directory" || !got.DryRun || len(got.Members) != 1 {
		t.Errorf("request: %+v", got)
	}

	// No members is an empty list, never null.
	raw := ""
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&m)
		raw = string(m["members"])
		w.Write([]byte(`{"added":[],"removed":[]}`))
	}))
	defer empty.Close()
	if _, err := groupsync.NewClient("projects", empty.URL, auth.StaticToken("t"), nil).Sync(context.Background(), groupsync.Request{OrgID: org, GroupID: group, Change: groupsync.ChangeDeleted}); err != nil || raw != "[]" {
		t.Errorf("empty group: %v %q", err, raw)
	}

	// Anything but 200 is an error.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if _, err := groupsync.NewClient("projects", down.URL, auth.StaticToken("t"), nil).Sync(context.Background(), groupsync.Request{OrgID: org, GroupID: group}); err == nil {
		t.Error("a 503 was taken as done")
	}
}
