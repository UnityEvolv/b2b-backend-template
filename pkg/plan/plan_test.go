package plan_test

import (
	"strings"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
)

// The story's "done when": each refusal on free names the plan, the team-50
// user cap names team-200, and nothing on enterprise is capped in the product.
func TestFreeIsRefusedWhereTheStorySays(t *testing.T) {
	refused := func(name string, err error, limit string, required plan.Band) {
		t.Helper()
		r, ok := plan.AsRefusal(err)
		if !ok {
			t.Errorf("%s: not refused", name)
			return
		}
		if r.Plan != plan.Free || r.Limit != limit || r.Required != required || !strings.Contains(r.Message, "free") {
			t.Errorf("%s: %+v", name, r)
		}
		if f := r.Fields(); f["plan"] != "free" || f["limit"] != limit || (required != "" && f["required_plan"] != string(required)) {
			t.Errorf("%s: fields %v", name, f)
		}
	}
	refused("eleventh user", plan.CheckUsers(plan.Free, 10), "users", plan.Team50)
	refused("sixth office", plan.CheckOffices(plan.Free, 5), "offices", plan.Team50)
	refused("guest invite", plan.CheckFeature(plan.Free, plan.GuestInvites), "guest_invites", plan.Team50)
	refused("office admin", plan.CheckFeature(plan.Free, plan.OfficeAdminRole), "office_admin_role", plan.Team50)
	refused("recording", plan.CheckFeature(plan.Free, plan.CallRecording), "call_recording", plan.Team50)
	refused("messaging provider", plan.CheckFeature(plan.Free, plan.BringOwnMessaging), "bring_own_messaging", plan.Team50)
	refused("retention change", plan.CheckRetention(plan.Free, 24*time.Hour), "message_retention", plan.Team50)
	refused("scim", plan.CheckFeature(plan.Free, plan.SCIM), "scim", plan.Enterprise)
	refused("big attachment", plan.CheckAttachment(plan.Free, 11<<20), "attachment_bytes", plan.Team50)

	// Up to the cap is fine; the wall is soft.
	if err := plan.CheckUsers(plan.Free, 9); err != nil {
		t.Errorf("tenth user refused: %v", err)
	}
	if err := plan.CheckOffices(plan.Free, 4); err != nil {
		t.Errorf("fifth office refused: %v", err)
	}
	if err := plan.CheckAttachment(plan.Free, 10<<20); err != nil {
		t.Errorf("10 MB refused on free: %v", err)
	}
}

func TestTeam50NamesTeam200(t *testing.T) {
	r, ok := plan.AsRefusal(plan.CheckUsers(plan.Team50, 50))
	if !ok || r.Required != plan.Team200 || !strings.Contains(r.Message, "team-200") || !strings.Contains(r.Message, "team-50") {
		t.Errorf("%+v", r)
	}
	if err := plan.CheckUsers(plan.Team50, 49); err != nil {
		t.Errorf("fiftieth user refused: %v", err)
	}
	// Retention is configurable within bounds on team.
	if err := plan.CheckRetention(plan.Team50, 30*24*time.Hour); err != nil {
		t.Error(err)
	}
	if err := plan.CheckRetention(plan.Team50, 31*24*time.Hour); err == nil {
		t.Error("31 days accepted on team")
	}
	if err := plan.CheckRetention(plan.Team50, time.Hour); err == nil {
		t.Error("1 hour accepted on team")
	}
}

func TestEnterpriseHasNoProductCap(t *testing.T) {
	for _, err := range []error{
		plan.CheckUsers(plan.Enterprise, 100000), plan.CheckOffices(plan.Enterprise, 1000),
		plan.CheckFeature(plan.Enterprise, plan.SCIM), plan.CheckFeature(plan.Enterprise, plan.AuditExport),
		plan.CheckFeature(plan.Enterprise, plan.CustomerHostedDataPlane), plan.CheckRetention(plan.Enterprise, 20*24*time.Hour),
	} {
		if err != nil {
			t.Error(err)
		}
	}
	// And enterprise-only features are not on team.
	for _, f := range []plan.Feature{plan.SCIM, plan.AuditExport, plan.CustomerHostedDataPlane} {
		if err := plan.CheckFeature(plan.Team500, f); err == nil {
			t.Errorf("%s on team-500", f)
		}
	}
	if plan.Next(plan.Enterprise) != "" {
		t.Error("something above enterprise")
	}
}

func TestBandsParseAndOrder(t *testing.T) {
	for _, b := range plan.Bands {
		if got, err := plan.Parse(string(b)); err != nil || got != b {
			t.Errorf("%s: %v %v", b, got, err)
		}
	}
	if _, err := plan.Parse("gold"); err == nil {
		t.Error("gold parsed")
	}
	if plan.Rank(plan.Free) >= plan.Rank(plan.Team50) || plan.Rank(plan.Team500) >= plan.Rank(plan.Enterprise) || plan.Rank("gold") != -1 {
		t.Error("ranks out of order")
	}
	// An unknown band gets free's limits, never more.
	if plan.For("gold").Users != plan.For(plan.Free).Users {
		t.Error("unknown band is not treated as free")
	}
	if plan.BuiltInRoomCapacity != 4 {
		t.Error("the built-in provider is 4 per room on every plan")
	}
}

func TestDowngradeChecklist(t *testing.T) {
	// team-200 to free: every team door closes, and the caps drop.
	codes := map[string]bool{}
	for _, c := range plan.Downgrade(plan.Team200, plan.Free) {
		codes[c.Code] = true
		if c.Message == "" {
			t.Errorf("%s has no message", c.Code)
		}
	}
	for _, want := range []string{"office_admins_kept", "restricted_offices_kept", "guest_grants_run_out", "offices_over_limit_kept", "users_over_cap_kept", "rooms_keep_capacity", "calls_finish_on_provider", "recording_finishes", "messages_stay_on_provider", "retention_drops_forward", "attachments_smaller"} {
		if !codes[want] {
			t.Errorf("team-200 to free lacks %s: %v", want, codes)
		}
	}
	if codes["scim_stops"] {
		t.Error("team-200 never had SCIM")
	}
	// team-500 to team-50: only the user cap moves.
	if list := plan.Downgrade(plan.Team500, plan.Team50); len(list) != 1 || list[0].Code != "users_over_cap_kept" {
		t.Errorf("team-500 to team-50: %v", list)
	}
	// An upgrade closes nothing.
	if list := plan.Downgrade(plan.Free, plan.Team50); len(list) != 0 {
		t.Errorf("upgrade has consequences: %v", list)
	}
	// Nothing in the checklist deletes or removes.
	for _, c := range plan.Downgrade(plan.Enterprise, plan.Free) {
		if strings.Contains(strings.ToLower(c.Message), "delete") || strings.Contains(strings.ToLower(c.Message), "removed") {
			t.Errorf("%s deletes or removes: %s", c.Code, c.Message)
		}
	}
}
