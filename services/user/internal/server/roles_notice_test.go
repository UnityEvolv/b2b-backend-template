package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/server"
)

// A role change is a membership notice to the person, in the org it
// changed in, naming the new role and nothing personal; setting the same
// role again tells nobody.
func TestARoleChangeIsNoticed(t *testing.T) {
	f := newAPI(t)
	m := f.signIn(t, acme, "uma@example.com", "Uma", nil)
	membership := id(t, m, "membership", "id")
	path := "/v1/internal/organizations/" + acme.String() + "/memberships/" + membership + "/role"
	for _, role := range []string{"billing_admin", "billing_admin"} {
		if status, out := f.do(t, http.MethodPut, path, f.service(t, "authorization"), map[string]any{"role": role}); status != http.StatusOK {
			t.Fatalf("role: %d %v", status, out)
		}
	}
	var got []server.Notice
	f.notices.mu.Lock()
	for _, n := range f.notices.sent {
		if n.Kind == "role_changed" {
			got = append(got, n)
		}
	}
	f.notices.mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("noticed %+v", got)
	}
	n := got[0]
	if n.Category != notifycat.Membership || n.OrgID != acme.String() || n.Audience != "" ||
		len(n.Recipients) != 1 || n.Recipients[0].String() != membership || n.Data["role"] != "Billing Admin" || n.Link == "" {
		t.Errorf("notice %+v", n)
	}
	raw, _ := json.Marshal(n)
	if strings.Contains(string(raw), "@") || strings.Contains(string(raw), "Uma") {
		t.Errorf("notice carries personal data: %s", raw)
	}
}
