package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// platformInvites is every invite into the platform org, as an operator lists them.
func (f *fixture) platformInvites(t *testing.T) []map[string]any {
	t.Helper()
	rec := f.browser().do(http.MethodGet, "/v1/organizations/"+auth.PlatformOrg+"/invites", f.platform(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list platform invites: %d %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	for _, inv := range body(t, rec)["invites"].([]any) {
		out = append(out, inv.(map[string]any))
	}
	return out
}

// The first operator: with nobody in the platform org, a start invites the
// configured address as its Owner, once. Later starts do nothing while the
// invite is open or once it has been accepted.
func TestBootstrapInvitesTheFirstOperatorOnce(t *testing.T) {
	f := newAPI(t)
	ctx := context.Background()

	sent, err := f.srv.BootstrapOperator(ctx, "Operator@Example.com")
	if err != nil || !sent {
		t.Fatalf("first start: sent %v, %v", sent, err)
	}
	invites := f.platformInvites(t)
	if len(invites) != 1 || invites[0]["email"] != "operator@example.com" || invites[0]["role"] != "owner" || invites[0]["status"] != "pending" {
		t.Fatalf("invites after the first start: %v", invites)
	}
	msg, token := f.lastLink(t)
	if msg.Template != "invite" || msg.To != "operator@example.com" || msg.OrgName == "" || msg.OrgID != auth.PlatformOrg {
		t.Errorf("email: %+v", msg)
	}
	if f.audited("invite.sent") != 1 {
		t.Errorf("sending audited %d times", f.audited("invite.sent"))
	}
	for _, ev := range f.recorder.events {
		if ev.Action == "invite.sent" && ev.Details["bootstrap"] != true {
			t.Errorf("bootstrap invite audited without saying so: %+v", ev)
		}
	}

	// A second start with the invite still open: nothing new.
	if sent, err := f.srv.BootstrapOperator(ctx, "operator@example.com"); err != nil || sent {
		t.Errorf("second start: sent %v, %v", sent, err)
	}
	if n := len(f.platformInvites(t)); n != 1 || f.sentCount() != 1 {
		t.Errorf("after the second start: %d invites, %d emails", n, f.sentCount())
	}

	// Accepted: the operator is a member of the platform org, and a start
	// naming anyone at all does nothing.
	rec := f.browser().do(http.MethodPost, "/v1/invites/"+token+"/accept", "", map[string]any{"name": "Operator"})
	if rec.Code != http.StatusOK || body(t, rec)["org_id"] != auth.PlatformOrg {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if sent, err := f.srv.BootstrapOperator(ctx, "someone-else@example.com"); err != nil || sent {
		t.Errorf("start with an operator: sent %v, %v", sent, err)
	}
	if n := len(f.platformInvites(t)); n != 1 {
		t.Errorf("invites after acceptance: %d", n)
	}
}

// An invite that lapsed unaccepted is no longer open, so the next start
// sends a fresh one.
func TestBootstrapReinvitesAfterTheInviteLapses(t *testing.T) {
	f := newAPI(t)
	ctx := context.Background()
	if sent, err := f.srv.BootstrapOperator(ctx, "operator@example.com"); err != nil || !sent {
		t.Fatalf("first start: sent %v, %v", sent, err)
	}
	_, token := f.lastLink(t)
	f.age2(t, "invites", "expires_at", token, 8*24*time.Hour)
	if sent, err := f.srv.BootstrapOperator(ctx, "operator@example.com"); err != nil || !sent {
		t.Fatalf("start after the invite lapsed: sent %v, %v", sent, err)
	}
	if f.sentCount() != 2 {
		t.Errorf("emails: %d", f.sentCount())
	}
}

// With an operator already in the platform org, nothing is sent.
func TestBootstrapDoesNothingWithAMember(t *testing.T) {
	f := newAPI(t)
	f.users.add("existing@example.com", uuid.MustParse(auth.PlatformOrg), "active", nil)
	if sent, err := f.srv.BootstrapOperator(context.Background(), "operator@example.com"); err != nil || sent {
		t.Errorf("start with a member: sent %v, %v", sent, err)
	}
	if n := len(f.platformInvites(t)); n != 0 || f.sentCount() != 0 {
		t.Errorf("%d invites, %d emails", n, f.sentCount())
	}
	// A member who has left does not count: nobody active is nobody.
	g := newAPI(t)
	g.users.add("gone@example.com", uuid.MustParse(auth.PlatformOrg), "left", nil)
	if sent, err := g.srv.BootstrapOperator(context.Background(), "operator@example.com"); err != nil || !sent {
		t.Errorf("start with only a former member: sent %v, %v", sent, err)
	}
}

// With the variable empty, or not an address, nothing happens.
func TestBootstrapDoesNothingWithoutAnAddress(t *testing.T) {
	f := newAPI(t)
	for _, address := range []string{"", "   ", "not an address"} {
		if sent, err := f.srv.BootstrapOperator(context.Background(), address); err != nil || sent {
			t.Errorf("%q: sent %v, %v", address, sent, err)
		}
	}
	if n := len(f.platformInvites(t)); n != 0 || f.sentCount() != 0 {
		t.Errorf("%d invites, %d emails", n, f.sentCount())
	}
}
