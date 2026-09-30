package plan_test

import (
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
)

// The default ladder: each refusal on free names the plan and the band that
// would allow it, and nothing on the contractual band is capped.
func TestDefaultLadder(t *testing.T) {
	refused := func(name string, err error, limit string, required plan.Band) {
		t.Helper()
		r, ok := plan.AsRefusal(err)
		if !ok {
			t.Errorf("%s: not refused", name)
			return
		}
		if r.Plan != "free" || r.Limit != limit || r.Required != required || !strings.Contains(r.Message, "free") {
			t.Errorf("%s: %+v", name, r)
		}
		if f := r.Fields(); f["plan"] != "free" || f["limit"] != limit || (required != "" && f["required_plan"] != string(required)) {
			t.Errorf("%s: fields %v", name, f)
		}
	}
	refused("eleventh user", plan.CheckUsers("free", 10), "users", "team")
	refused("scim", plan.CheckFeature("free", plan.SCIM), "scim", "enterprise")

	// Up to the cap is fine; the wall is soft.
	if err := plan.CheckUsers("free", 9); err != nil {
		t.Errorf("tenth user refused: %v", err)
	}
	r, ok := plan.AsRefusal(plan.CheckUsers("team", 50))
	if !ok || r.Required != "business" || !strings.Contains(r.Message, "business") {
		t.Errorf("%+v", r)
	}
	for _, err := range []error{plan.CheckUsers("enterprise", 100000), plan.CheckFeature("enterprise", plan.SCIM), plan.CheckFeature("enterprise", plan.AuditExport)} {
		if err != nil {
			t.Error(err)
		}
	}
	if err := plan.CheckFeature("business", plan.SCIM); err == nil {
		t.Error("SCIM on business")
	}
	if plan.Next("enterprise") != "" || !plan.Contractual("enterprise") || plan.Contractual("team") || plan.Lowest() != "free" {
		t.Error("ladder shape")
	}
	if got := plan.SelfServe(); len(got) != 2 || got[0] != "team" || got[1] != "business" {
		t.Errorf("self-serve bands: %v", got)
	}
}

func TestBandsParseAndOrder(t *testing.T) {
	for _, b := range plan.Bands() {
		if got, err := plan.Parse(string(b)); err != nil || got != b {
			t.Errorf("%s: %v %v", b, got, err)
		}
	}
	if _, err := plan.Parse("gold"); err == nil {
		t.Error("gold parsed")
	}
	if plan.Rank("free") >= plan.Rank("team") || plan.Rank("business") >= plan.Rank("enterprise") || plan.Rank("gold") != -1 {
		t.Error("ranks out of order")
	}
	// An unknown band gets the lowest band's limits, never more.
	if plan.For("gold").Cap(plan.Users) != plan.For("free").Cap(plan.Users) {
		t.Error("unknown band is not treated as the lowest")
	}
	d := plan.Describe("enterprise")
	if d.Limits["users"] != plan.Unlimited || len(d.Features) != 3 || !d.Contractual {
		t.Errorf("described: %+v", d)
	}
}

// A product registers its own ladder, limit, feature and consequence, and
// every gate reads them: the fake limit is refused at the cap and the
// checklist carries the product's line.
func TestProductRegistersItsOwnLimits(t *testing.T) {
	r := plan.New()
	r.RegisterLimit(plan.LimitSpec{Key: "projects", Label: "projects"})
	r.RegisterFeature(plan.FeatureSpec{Key: "exports", Label: "scheduled exports", LostCode: "exports_stop", LostMessage: "Scheduled exports stop; the files already made stay."})
	r.RegisterConsequence(func(from, to plan.BandSpec) []plan.Consequence {
		if to.Cap("projects") != plan.Unlimited && to.Cap("projects") < from.Cap("projects") {
			return []plan.Consequence{{Code: "projects_read_only", Message: "Projects beyond the cap become read-only; nothing is deleted."}}
		}
		return nil
	})
	r.SetBands([]plan.BandSpec{
		{Name: "starter", Limits: map[plan.Limit]int{plan.Users: 3, "projects": 2}},
		{Name: "pro", Limits: map[plan.Limit]int{plan.Users: 30, "projects": 20}, Features: []plan.Feature{"exports"}},
		{Name: "scale", Features: []plan.Feature{"exports", plan.SCIM}, Contractual: true},
	})

	if err := r.CheckLimit("starter", "projects", 1); err != nil {
		t.Errorf("second project refused: %v", err)
	}
	ref, ok := plan.AsRefusal(r.CheckLimit("starter", "projects", 2))
	if !ok || ref.Limit != "projects" || ref.Required != "pro" || !strings.Contains(ref.Message, "2 projects") {
		t.Fatalf("third project: %+v", ref)
	}
	// Required is the first band whose cap fits, not merely the next one.
	if ref, _ := plan.AsRefusal(r.CheckLimit("starter", "projects", 25)); ref.Required != "scale" {
		t.Errorf("twenty-sixth project: %+v", ref)
	}
	if ref, _ := plan.AsRefusal(r.CheckFeature("starter", "exports")); ref.Required != "pro" || !strings.Contains(ref.Message, "scheduled exports") {
		t.Errorf("exports on starter: %+v", ref)
	}
	// Nothing above allows it: the refusal names no band rather than one
	// that would refuse too.
	r.RegisterFeature(plan.FeatureSpec{Key: "archive", Label: "the archive"})
	if ref, _ := plan.AsRefusal(r.CheckFeature("pro", "archive")); ref == nil || ref.Required != "" || strings.Contains(ref.Message, "above") {
		t.Errorf("archive on pro: %+v", ref)
	}
	// A limit nobody registered never refuses.
	if err := r.CheckLimit("starter", "widgets", 1000); err != nil {
		t.Error(err)
	}
	codes := map[string]bool{}
	for _, c := range r.Downgrade("pro", "starter") {
		codes[c.Code] = true
	}
	for _, want := range []string{"users_over_cap_kept", "projects_over_cap_kept", "exports_stop", "projects_read_only"} {
		if !codes[want] {
			t.Errorf("pro to starter lacks %s: %v", want, codes)
		}
	}
	if list := r.Downgrade("starter", "pro"); len(list) != 0 {
		t.Errorf("upgrade has consequences: %v", list)
	}
	// The template's own registry is untouched.
	if _, err := plan.Parse("pro"); err == nil {
		t.Error("a product registry leaked into the default")
	}
}

func TestDowngradeChecklistNeverDeletes(t *testing.T) {
	for _, c := range plan.Downgrade("enterprise", "free") {
		if c.Message == "" || strings.Contains(strings.ToLower(c.Message), "delete") || strings.Contains(strings.ToLower(c.Message), "removed") {
			t.Errorf("%s deletes or removes: %q", c.Code, c.Message)
		}
	}
	if list := plan.Downgrade("business", "team"); len(list) != 1 || list[0].Code != "users_over_cap_kept" {
		t.Errorf("business to team: %v", list)
	}
}
