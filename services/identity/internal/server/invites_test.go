package server_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// owner is an Owner's token at org, with every permission.
func (f *fixture) owner(t *testing.T, org uuid.UUID) (string, string) {
	t.Helper()
	id := uuid.NewString()
	f.grants[org.String()+"/"+id] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	raw, err := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org.String(), MembershipID: id}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw, id
}

// The story's "done when": an invite can be created, accepted once, and
// refused on a second attempt, after expiry, or at the org's user cap.
func TestInviteIsCreatedAcceptedOnceAndRefusedAfter(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	owner, ownerID := f.owner(t, acme)
	path := "/v1/organizations/" + acme.String() + "/invites"

	// The shape is checked; a User may not invite; an Admin may not invite an Owner.
	for _, bad := range []map[string]any{{"email": "nope"}, {"email": "x@example.com", "role": "guest"}, {"email": "x@example.com", "app": "shop"}} {
		if rec := b.do(http.MethodPost, path, owner, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, rec.Code)
		}
	}
	user, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: uuid.NewString()}, time.Hour)
	if rec := b.do(http.MethodPost, path, user, map[string]any{"email": "x@example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("a User inviting: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, path, f.admin(t, acme), map[string]any{"email": "x@example.com", "role": "owner"}); rec.Code != http.StatusForbidden {
		t.Errorf("an Admin inviting an Owner: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, path, owner, map[string]any{"email": "x@example.com", "role": "owner"}); rec.Code != http.StatusForbidden {
		t.Errorf("an Owner inviting an Owner: %d", rec.Code)
	}
	// An address already in is refused with a reason.
	f.users.add("here@acme.com", acme, "active", nil)
	if rec := b.do(http.MethodPost, path, owner, map[string]any{"email": "here@acme.com"}); rec.Code != http.StatusConflict || body(t, rec)["code"] != "invite.already_member" {
		t.Errorf("inviting a member: %d %s", rec.Code, rec.Body.String())
	}

	// Made: emailed on the org's behalf with a link into the app, recorded.
	rec := b.do(http.MethodPost, path, owner, map[string]any{"email": "Ada@Example.com", "role": "admin", "app": "admin", "expires_in_hours": 48})
	inv := body(t, rec)
	if rec.Code != http.StatusCreated || inv["status"] != "pending" || inv["email"] != "ada@example.com" || inv["role"] != "admin" || inv["invited_by_membership_id"] != ownerID {
		t.Fatalf("create: %d %v", rec.Code, inv)
	}
	msg, token := f.lastLink(t)
	if msg.Template != "invite" || msg.OrgName != "Acme" || msg.To != "ada@example.com" || !strings.HasPrefix(msg.Data["link"].(string), "http://admin.test/accept-invite?token=") {
		t.Errorf("email: %+v", msg)
	}
	if f.audited("invite.sent") != 1 {
		t.Errorf("sending audited %d times", f.audited("invite.sent"))
	}
	// Sending again for the same address reissues: one invite, a new link,
	// the old one dead.
	rec = b.do(http.MethodPost, path, owner, map[string]any{"email": "ada@example.com"})
	if rec.Code != http.StatusCreated || body(t, rec)["invite_id"] != inv["invite_id"] {
		t.Errorf("second invite for the same address: %d %v", rec.Code, body(t, rec))
	}
	_, token2 := f.lastLink(t)
	if rec := b.do(http.MethodGet, "/v1/invites/"+token, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("old link after reissue: %d", rec.Code)
	}
	// The acceptance page: what it is for, without the whole address.
	rec = b.do(http.MethodGet, "/v1/invites/"+token2, "", nil)
	preview := body(t, rec)
	if rec.Code != http.StatusOK || preview["org_name"] != "Acme" || preview["kind"] != "member" || preview["email_hint"] != "a***@example.com" {
		t.Errorf("preview: %d %v", rec.Code, preview)
	}
	// Listed, and the listing is paginated.
	rec = b.do(http.MethodGet, path+"?status=pending&limit=1", owner, nil)
	page := body(t, rec)
	if rec.Code != http.StatusOK || len(page["invites"].([]any)) != 1 {
		t.Errorf("list: %d %v", rec.Code, page)
	}
	if rec := b.do(http.MethodGet, path, user, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a User listing all: %d", rec.Code)
	}
	if rec := b.do(http.MethodGet, path+"?mine=true", user, nil); rec.Code != http.StatusOK || len(body(t, rec)["invites"].([]any)) != 0 {
		t.Errorf("a User listing theirs: %d %s", rec.Code, rec.Body.String())
	}

	// Accepted once: a local org, so the person gets a verification link
	// and sets a password next. The membership was asked for with the role.
	rec = b.do(http.MethodPost, "/v1/invites/"+token2+"/accept", "", map[string]any{"name": "Ada"})
	accepted := body(t, rec)
	if rec.Code != http.StatusOK || accepted["next"] != "verify_email" || accepted["org_id"] != acme.String() {
		t.Fatalf("accept: %d %v", rec.Code, accepted)
	}
	if len(f.users.created) != 1 || f.users.created[0].Role != "admin" || f.users.created[0].Source != "invite" || f.users.created[0].Name != "Ada" {
		t.Errorf("membership asked for: %+v", f.users.created)
	}
	if msg, _ := f.lastLink(t); msg.Template != "verify_email" || msg.To != "ada@example.com" {
		t.Errorf("after accepting: %+v", msg)
	}
	if f.audited("invite.accepted") != 1 {
		t.Errorf("acceptance audited %d times", f.audited("invite.accepted"))
	}
	// A second attempt is refused as used; so is resending or revoking it.
	if rec := b.do(http.MethodPost, "/v1/invites/"+token2+"/accept", "", nil); rec.Code != http.StatusNotFound || body(t, rec)["code"] != "invite.used" {
		t.Errorf("accepting twice: %d %s", rec.Code, rec.Body.String())
	}
	id := inv["invite_id"].(string)
	if rec := b.do(http.MethodPost, path+"/"+id+"/resend", owner, nil); rec.Code != http.StatusConflict {
		t.Errorf("resending an accepted invite: %d", rec.Code)
	}
	if rec := b.do(http.MethodDelete, path+"/"+id, owner, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking an accepted invite: %d", rec.Code)
	}
	// Now a member: inviting again is refused.
	if rec := b.do(http.MethodPost, path, owner, map[string]any{"email": "ada@example.com"}); rec.Code != http.StatusConflict {
		t.Errorf("inviting an accepted member: %d", rec.Code)
	}

	// Expired: refused, then resent with a fresh link that works.
	rec = b.do(http.MethodPost, path, owner, map[string]any{"email": "bob@example.com", "expires_in_hours": 1})
	bobInvite := body(t, rec)["invite_id"].(string)
	_, bobToken := f.lastLink(t)
	f.age2(t, "invites", "expires_at", bobToken, 2*time.Hour)
	if rec := b.do(http.MethodPost, "/v1/invites/"+bobToken+"/accept", "", nil); rec.Code != http.StatusNotFound || body(t, rec)["code"] != "invite.expired" {
		t.Errorf("expired: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, path+"/"+bobInvite+"/resend", owner, map[string]any{"expires_in_hours": 24}); rec.Code != http.StatusOK || body(t, rec)["status"] != "pending" {
		t.Errorf("resend: %d %s", rec.Code, rec.Body.String())
	}
	_, bobToken2 := f.lastLink(t)
	// At the org's cap: refused, and the invite stays open for after the upgrade.
	f.users.capped[acme] = true
	if rec := b.do(http.MethodPost, "/v1/invites/"+bobToken2+"/accept", "", nil); rec.Code != http.StatusConflict || body(t, rec)["code"] != "plan.limit_reached" {
		t.Errorf("at the cap: %d %s", rec.Code, rec.Body.String())
	}
	f.users.capped[acme] = false
	if rec := b.do(http.MethodPost, "/v1/invites/"+bobToken2+"/accept", "", nil); rec.Code != http.StatusOK {
		t.Errorf("after the upgrade: %d %s", rec.Code, rec.Body.String())
	}

	// Revoked: the link stops working; a User cannot revoke someone else's.
	b.do(http.MethodPost, path, owner, map[string]any{"email": "carol@example.com"})
	carol := body(t, b.do(http.MethodGet, path+"?status=pending", owner, nil))["invites"].([]any)[0].(map[string]any)
	_, carolToken := f.lastLink(t)
	if rec := b.do(http.MethodDelete, path+"/"+carol["invite_id"].(string), user, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a User revoking: %d", rec.Code)
	}
	if rec := b.do(http.MethodDelete, path+"/"+carol["invite_id"].(string), owner, nil); rec.Code != http.StatusNoContent {
		t.Errorf("revoke: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, "/v1/invites/"+carolToken+"/accept", "", nil); rec.Code != http.StatusNotFound || body(t, rec)["code"] != "invite.revoked" {
		t.Errorf("revoked: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodGet, "/v1/invites/not-a-token", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown token: %d", rec.Code)
	}
}

// The other two flows: an operator invites the first Owner of an Entra
// org, who then signs in through the provider; a service invites a guest
// into one room, who gets a local account even in an Entra org.
func TestOwnerAndGuestInvites(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	b := f.browser()
	path := "/v1/organizations/" + acme.String() + "/invites"

	rec := b.do(http.MethodPost, path, f.platform(), map[string]any{"email": "owner@acme.com", "role": "owner", "app": "admin"})
	if rec.Code != http.StatusCreated || body(t, rec)["invited_by_membership_id"] != nil {
		t.Fatalf("operator inviting an owner: %d %s", rec.Code, rec.Body.String())
	}
	_, token := f.lastLink(t)
	rec = b.do(http.MethodPost, "/v1/invites/"+token+"/accept", "", map[string]any{"name": "Olivia"})
	if out := body(t, rec); rec.Code != http.StatusOK || out["next"] != "sign_in_entra" {
		t.Fatalf("owner accepting: %d %v", rec.Code, out)
	}
	if f.users.created[0].Role != "owner" || f.users.created[0].Kind != "member" {
		t.Errorf("owner membership: %+v", f.users.created[0])
	}

	// A guest: one room, a purpose, a short expiry, sent by a member.
	member := f.users.add("host@acme.com", acme, "active", nil)
	room := uuid.New()
	guest := map[string]any{"org_id": acme, "email": "guest@elsewhere.example", "kind": "guest", "room_id": room, "purpose": "Design review", "app": "ofis", "expires_in_hours": 4, "invited_by_membership_id": member.ID}
	if rec := b.do(http.MethodPost, "/v1/internal/invites", f.platform(), guest); rec.Code != http.StatusForbidden {
		t.Errorf("a person on the internal endpoint: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, "/v1/internal/invites", f.service("billing"), map[string]any{"org_id": acme, "email": "guest@elsewhere.example", "kind": "guest", "app": "ofis"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a guest with no room: %d", rec.Code)
	}
	rec = b.do(http.MethodPost, "/v1/internal/invites", f.service("billing"), guest)
	inv := body(t, rec)
	if rec.Code != http.StatusCreated || inv["kind"] != "guest" || inv["role"] != "guest" || inv["room_id"] != room.String() || inv["purpose"] != "Design review" {
		t.Fatalf("guest invite: %d %v", rec.Code, inv)
	}
	msg, guestToken := f.lastLink(t)
	if msg.Data["purpose"] != "Design review" || !strings.Contains(msg.Data["what"].(string), "guest") {
		t.Errorf("guest email: %+v", msg.Data)
	}
	// A member's address cannot be a guest.
	if rec := b.do(http.MethodPost, "/v1/internal/invites", f.service("billing"), map[string]any{"org_id": acme, "email": "host@acme.com", "kind": "guest", "room_id": room, "app": "ofis"}); rec.Code != http.StatusConflict || !strings.Contains(body(t, rec)["message"].(string), "office") {
		t.Errorf("a member as a guest: %d %s", rec.Code, rec.Body.String())
	}
	// The inviter sees it under "mine" and can extend it; nobody else's shows.
	host, _ := f.sig.Issue(auth.Caller{UserID: member.User.ID.String(), OrgID: acme.String(), MembershipID: member.ID.String()}, time.Hour)
	mine := body(t, b.do(http.MethodGet, path+"?mine=true", host, nil))["invites"].([]any)
	if len(mine) != 1 {
		t.Errorf("host's invites: %v", mine)
	}
	if rec := b.do(http.MethodPost, path+"/"+inv["invite_id"].(string)+"/resend", host, map[string]any{"expires_in_hours": 8}); rec.Code != http.StatusOK {
		t.Errorf("host extending: %d %s", rec.Code, rec.Body.String())
	}
	_, guestToken2 := f.lastLink(t)
	if rec := b.do(http.MethodGet, "/v1/invites/"+guestToken, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("old guest link: %d", rec.Code)
	}
	// Accepting: a guest membership by room invite, and a local account
	// even though acme signs members in through Entra.
	rec = b.do(http.MethodPost, "/v1/invites/"+guestToken2+"/accept", "", map[string]any{"name": "Gus"})
	if out := body(t, rec); rec.Code != http.StatusOK || out["next"] != "verify_email" {
		t.Fatalf("guest accepting: %d %v", rec.Code, out)
	}
	last := f.users.created[len(f.users.created)-1]
	if last.Kind != "guest" || last.Role != "guest" || last.Source != "room_invite" {
		t.Errorf("guest membership: %+v", last)
	}
	// And the room grant the invite carried is bound in the office service.
	if len(f.offices.accepted) != 1 || f.offices.accepted[0] != room {
		t.Errorf("grant bound: %v", f.offices.accepted)
	}
	// Someone with a password already is told to sign in.
	f.account(t, "dana@example.com", globex, "danas-long-password")
	owner, _ := f.owner(t, acme)
	b.do(http.MethodPost, path, owner, map[string]any{"email": "dana@example.com"})
	_, danaToken := f.lastLink(t)
	// (acme is an Entra org, so a member invite says Entra; make it a guest
	// invite instead, which always uses a local account.)
	b.do(http.MethodPost, "/v1/internal/invites", f.service("billing"), map[string]any{"org_id": acme, "email": "dana@example.com", "kind": "guest", "room_id": room, "app": "ofis"})
	_, danaGuest := f.lastLink(t)
	if out := body(t, b.do(http.MethodPost, "/v1/invites/"+danaGuest+"/accept", "", nil)); out["next"] != "sign_in" {
		t.Errorf("a person with a password: %v", out)
	}
	_ = danaToken
}
