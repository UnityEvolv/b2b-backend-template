package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// An Owner transfers to a member who accepts, the
// previous Owner ends as an Admin, and an unaccepted request expires
// without changing anything.
func TestOwnershipTransfer(t *testing.T) {
	f := newAPI(t)
	owner := f.people.add(acme, authz.Owner, "active")
	admin := f.people.add(acme, authz.Admin, "active")
	user := f.people.add(acme, authz.User, "active")
	guest := f.people.add(acme, authz.Guest, "active")
	gone := f.people.add(acme, authz.User, "deactivated")
	path := "/v1/organizations/" + acme.String() + "/ownership-transfers"

	// Only an Owner asks; the target must be an active member, not a guest,
	// not themselves.
	if status, _ := f.do(http.MethodPost, path, f.as(acme, admin), map[string]any{"to_membership_id": user}); status != http.StatusForbidden {
		t.Errorf("an Admin asking: %d", status)
	}
	for _, bad := range []uuid.UUID{owner, guest, gone} {
		if status, _ := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": bad}); status != http.StatusBadRequest {
			t.Errorf("target %s: %d", bad, status)
		}
	}
	if status, _ := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": uuid.New()}); status != http.StatusNotFound {
		t.Error("a stranger as target was not 404")
	}

	// Asked: the target is emailed, both parties see it, nobody else does,
	// and nothing has changed yet.
	status, out := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": admin})
	if status != http.StatusCreated || out["status"] != "pending" || out["to_membership_id"] != admin.String() {
		t.Fatalf("request: %d %v", status, out)
	}
	first := out["transfer_id"].(string)
	if len(f.mail.sent) != 1 || f.mail.sent[0].Template != "ownership_transfer_requested" || f.mail.sent[0].To != admin.String()[:8]+"@example.com" || f.mail.sent[0].OrgName == "" {
		t.Errorf("email: %+v", f.mail.sent)
	}
	for who, want := range map[uuid.UUID]int{owner: 1, admin: 1, user: 0} {
		_, list := f.do(http.MethodGet, path, f.as(acme, who), nil)
		if got := len(list["transfers"].([]any)); got != want {
			t.Errorf("%s sees %d transfers, want %d", who, got, want)
		}
	}
	if role := f.people.rows[f.people.key(acme, admin)].Role; role != authz.Admin {
		t.Errorf("target changed before accepting: %s", role)
	}
	// Nobody but the person asked accepts.
	if status, _ := f.do(http.MethodPost, path+"/"+first+"/accept", f.as(acme, user), nil); status != http.StatusForbidden {
		t.Errorf("a bystander accepting: %d", status)
	}
	if status, _ := f.do(http.MethodPost, path+"/"+first+"/accept", f.as(acme, owner), nil); status != http.StatusForbidden {
		t.Errorf("the owner accepting their own: %d", status)
	}
	// A new request replaces the old; the old cannot be accepted.
	_, second := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": user})
	if status, out := f.do(http.MethodPost, path+"/"+first+"/accept", f.as(acme, admin), nil); status != http.StatusConflict || out["code"] != "ownership_transfer.not_open" {
		t.Errorf("accepting a replaced request: %d %v", status, out)
	}
	// The target declines; the Owner asks again and withdraws; nothing changed.
	secondID := second["transfer_id"].(string)
	if status, _ := f.do(http.MethodDelete, path+"/"+secondID, f.as(acme, user), nil); status != http.StatusNoContent {
		t.Errorf("declining: %d", status)
	}
	_, third := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": user})
	if status, _ := f.do(http.MethodDelete, path+"/"+third["transfer_id"].(string), f.as(acme, owner), nil); status != http.StatusNoContent {
		t.Errorf("withdrawing: %d", status)
	}
	if status, _ := f.do(http.MethodDelete, path+"/"+third["transfer_id"].(string), f.as(acme, owner), nil); status != http.StatusNotFound {
		t.Errorf("withdrawing twice: %d", status)
	}
	if f.people.rows[f.people.key(acme, owner)].Role != authz.Owner || f.people.rows[f.people.key(acme, user)].Role != authz.User {
		t.Error("roles changed without an acceptance")
	}

	// Accepted: the target is Owner, the previous Owner an Admin, both told, audited.
	_, fourth := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": admin})
	fourthID := fourth["transfer_id"].(string)
	sent := len(f.mail.sent)
	status, out = f.do(http.MethodPost, path+"/"+fourthID+"/accept", f.as(acme, admin), nil)
	if status != http.StatusOK || out["status"] != "accepted" || out["accepted_at"] == nil {
		t.Fatalf("accept: %d %v", status, out)
	}
	if f.people.rows[f.people.key(acme, admin)].Role != authz.Owner || f.people.rows[f.people.key(acme, owner)].Role != authz.Admin {
		t.Errorf("roles after: target %s, previous %s", f.people.rows[f.people.key(acme, admin)].Role, f.people.rows[f.people.key(acme, owner)].Role)
	}
	if len(f.mail.sent) != sent+2 || f.mail.sent[sent].Template != "ownership_transferred" {
		t.Errorf("emails after accepting: %+v", f.mail.sent[sent:])
	}
	if f.recorder.count("ownership.transferred") != 1 || f.recorder.count("ownership.transfer_requested") != 4 || f.recorder.count("ownership.transfer_declined") != 1 || f.recorder.count("ownership.transfer_cancelled") != 1 {
		t.Errorf("audit: %v", f.recorder.actions())
	}
	if status, _ := f.do(http.MethodPost, path+"/"+fourthID+"/accept", f.as(acme, admin), nil); status != http.StatusConflict {
		t.Errorf("accepting twice: %d", status)
	}
	// The former Owner, now an Admin, cannot ask; the new one can.
	if status, _ := f.do(http.MethodPost, path, f.as(acme, owner), map[string]any{"to_membership_id": user}); status != http.StatusForbidden {
		t.Errorf("the former owner asking: %d", status)
	}
	// Expired: nothing changes, and it cannot be accepted.
	_, fifth := f.do(http.MethodPost, path, f.as(acme, admin), map[string]any{"to_membership_id": user})
	f.expire(t, fifth["transfer_id"].(string))
	if status, out := f.do(http.MethodPost, path+"/"+fifth["transfer_id"].(string)+"/accept", f.as(acme, user), nil); status != http.StatusConflict || out["code"] != "ownership_transfer.not_open" {
		t.Errorf("accepting an expired request: %d %v", status, out)
	}
	if _, list := f.do(http.MethodGet, path, f.as(acme, user), nil); len(list["transfers"].([]any)) != 0 {
		t.Errorf("an expired request still listed: %v", list)
	}
	if f.people.rows[f.people.key(acme, user)].Role != authz.User {
		t.Error("an expired request changed a role")
	}
}

// expire moves a transfer's expiry into the past.
func (f *fixture) expire(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', 'system:test', true)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE ownership_transfers SET expires_at = now() - interval '1 hour' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	_ = time.Now
}
