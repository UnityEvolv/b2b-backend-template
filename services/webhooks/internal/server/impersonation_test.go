package server_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// A platform operator's support session, seeing the org as an Admin, reads
// the org's endpoints and deliveries like the Admin would; every write,
// from adding an endpoint to resending a delivery, is refused, and every
// request is in the org's audit log (docs/impersonation.md).
func TestASupportSessionReadsWebhooksButNeverChangesThem(t *testing.T) {
	f := newFixture(t)
	admin := f.admin(orgA)
	rcv := newReceiver(t)
	id, _ := f.create(orgA, admin, rcv.URL+"/hooks", "member.added")
	if status, out := f.emit(orgA, added(uuid.NewString())); status != http.StatusAccepted && status != http.StatusOK {
		t.Fatalf("emit: %d %v", status, out)
	}
	list := f.deliveries(orgA, admin, "")
	if len(list) == 0 {
		t.Fatal("no delivery to read")
	}
	delivery := list[0]["id"].(string)

	// The person seen as is an Admin of orgA.
	m := uuid.NewString()
	f.grants[orgA+"/"+m] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	support := f.token(auth.Caller{UserID: uuid.NewString(), OrgID: orgA, MembershipID: m,
		ImpersonatorID: uuid.NewString(), ImpersonationID: uuid.NewString(), ImpersonationGrantID: uuid.NewString()})
	before := len(f.audit.actions())

	base := "/v1/organizations/" + orgA
	for _, path := range []string{
		base + "/webhook-event-types", base + "/webhook-endpoints", base + "/webhook-endpoints/" + id,
		base + "/webhook-deliveries", base + "/webhook-deliveries/" + delivery,
	} {
		if status, out := f.call(http.MethodGet, path, support, nil); status != http.StatusOK {
			t.Errorf("read %s: %d %v", path, status, out)
		}
	}
	if _, got := f.call(http.MethodGet, base+"/webhook-endpoints/"+id, support, nil); got["secret"] != nil {
		t.Error("a support session read a secret")
	}

	for _, w := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, base + "/webhook-endpoints", map[string]any{"url": rcv.URL + "/other"}},
		{http.MethodPatch, base + "/webhook-endpoints/" + id, map[string]any{"enabled": false}},
		{http.MethodDelete, base + "/webhook-endpoints/" + id, nil},
		{http.MethodPost, base + "/webhook-endpoints/" + id + "/rotate-secret", map[string]any{}},
		{http.MethodPost, base + "/webhook-endpoints/" + id + "/test", map[string]any{}},
		{http.MethodPost, base + "/webhook-deliveries/" + delivery + "/resend", map[string]any{}},
	} {
		status, out := f.call(w.method, w.path, support, w.body)
		if status != http.StatusForbidden || out["code"] != auth.CodeImpersonationReadOnly {
			t.Errorf("%s %s: %d %v", w.method, w.path, status, out)
		}
	}
	// Nothing changed: the endpoint is still there, enabled, and the
	// receiver heard only the one event.
	if status, got := f.call(http.MethodGet, base+"/webhook-endpoints/"+id, admin, nil); status != http.StatusOK || got["enabled"] != true {
		t.Errorf("after the refused writes: %d %v", status, got)
	}
	if n := len(rcv.got()); n != 1 {
		t.Errorf("the receiver heard %d requests", n)
	}

	audited := f.audit.actions()[before:]
	// Six reads (the secret check included) and six refused writes.
	if len(audited) != 12 || strings.Count(strings.Join(audited, ","), audit.ActionImpersonatedRequest) != 12 {
		t.Errorf("audited %v", audited)
	}
}
