package plan_test

import (
	"strings"
	"testing"
	"time"

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
	if d.Limits["users"] != plan.Unlimited || len(d.Features) != 4 || !d.Contractual {
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

// A product running the template's services unchanged declares its ladder,
// limits and features in PLANS, and gets exactly what the code path gives:
// labels, caps, refusals and the checklist.
func TestPlansFromConfiguration(t *testing.T) {
	r := plan.New()
	err := r.Load(`{
		"limits":[{"key":"projects","label":"projects"},{"key":"storage_gb"}],
		"features":[{"key":"exports","label":"scheduled exports","lost_code":"exports_stop","lost_message":"Scheduled exports stop."}],
		"bands":[
			{"name":"starter","limits":{"users":3,"projects":2,"storage_gb":1}},
			{"name":"pro-30","label":"Pro","limits":{"users":30,"projects":20},"features":["exports"]},
			{"name":"scale","contractual":true,"features":["exports","scim"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Bands(); len(got) != 3 || got[0] != "starter" || r.Lowest() != "starter" || !r.Contractual("scale") {
		t.Errorf("ladder %v", got)
	}
	labels := map[plan.Band]string{}
	for _, b := range r.Ladder() {
		labels[b.Name] = b.Label
	}
	if labels["starter"] != "Starter" || labels["pro-30"] != "Pro" || labels["scale"] != "Scale" {
		t.Errorf("band labels %v", labels)
	}
	limitLabels := map[plan.Limit]string{}
	for _, l := range r.Limits() {
		limitLabels[l.Key] = l.Label
	}
	if limitLabels["users"] != "users" || limitLabels["projects"] != "projects" || limitLabels["storage_gb"] != "storage gb" {
		t.Errorf("limit labels %v", limitLabels)
	}
	for _, f := range r.Features() {
		if f.Label == "" {
			t.Errorf("feature %s has no label", f.Key)
		}
	}
	ref, ok := plan.AsRefusal(r.CheckLimit("starter", "projects", 2))
	if !ok || ref.Required != "pro-30" || !strings.Contains(ref.Message, "2 projects") {
		t.Errorf("third project: %+v", ref)
	}
	if ref, _ := plan.AsRefusal(r.CheckFeature("starter", "exports")); ref == nil || ref.Required != "pro-30" {
		t.Errorf("exports on starter: %+v", ref)
	}
	codes := map[string]bool{}
	for _, c := range r.Downgrade("pro-30", "starter") {
		codes[c.Code] = true
	}
	if !codes["projects_over_cap_kept"] || !codes["exports_stop"] {
		t.Errorf("checklist %v", codes)
	}

	// Limits and features alone keep the ladder; empty is nothing.
	keep := plan.New()
	keep.SetBands(plan.DefaultBands())
	if err := keep.Load(`{"limits":[{"key":"seats"}]}`); err != nil || len(keep.Bands()) != 4 || keep.For("free").Cap("seats") != plan.Unlimited {
		t.Errorf("limits only: %v %v", err, keep.Bands())
	}
	if err := keep.Load(""); err != nil {
		t.Error(err)
	}
}

// PLANS is checked as code registration is, and a bad value changes nothing.
func TestPlansConfigurationIsChecked(t *testing.T) {
	for name, s := range map[string]string{
		"not json":            `[`,
		"unknown field":       `{"tiers":[]}`,
		"unknown band field":  `{"bands":[{"name":"a","price":3}]}`,
		"empty ladder":        `{"bands":[]}`,
		"repeated band":       `{"bands":[{"name":"a"},{"name":"a"}]}`,
		"unnamed band":        `{"bands":[{"label":"A"}]}`,
		"unregistered limit":  `{"bands":[{"name":"a","limits":{"widgets":1}}]}`,
		"unregistered feat":   `{"bands":[{"name":"a","features":["warp"]}]}`,
		"negative cap":        `{"bands":[{"name":"a","limits":{"users":-1}}]}`,
		"limit with no key":   `{"limits":[{"label":"x"}]}`,
		"repeated feature":    `{"features":[{"key":"x"},{"key":"x"}]}`,
		"limit then bad band": `{"limits":[{"key":"projects"}],"bands":[{"name":"a","limits":{"widgets":1}}]}`,
	} {
		r := plan.New()
		r.SetBands(plan.DefaultBands())
		if err := r.Load(s); err == nil {
			t.Errorf("%s: loaded", name)
		}
		if len(r.Bands()) != 4 || len(r.Limits()) != 1 {
			t.Errorf("%s: the registry changed: %v %v", name, r.Bands(), r.Limits())
		}
	}
	// The code path panics on the same mistakes.
	for name, bands := range map[string][]plan.BandSpec{
		"empty":        {},
		"negative cap": {{Name: "a", Limits: map[plan.Limit]int{plan.Users: -1}}},
		"unregistered": {{Name: "a", Features: []plan.Feature{"warp"}}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: SetBands did not panic", name)
				}
			}()
			plan.New().SetBands(bands)
		}()
	}
}

// Every default band has a label, and the registry keeps its own copy of
// what it is given.
func TestBandLabelsAndCopies(t *testing.T) {
	for _, b := range plan.Ladder() {
		if b.Label == "" || b.Label[:1] != strings.ToUpper(b.Label[:1]) {
			t.Errorf("%s: label %q", b.Name, b.Label)
		}
	}
	if plan.Humanize("team-50") != "Team 50" || plan.Humanize("audit_export") != "Audit export" {
		t.Error("humanize")
	}
	r := plan.New()
	bands := []plan.BandSpec{{Name: "a", Limits: map[plan.Limit]int{plan.Users: 3}}}
	r.SetBands(bands)
	bands[0].Limits[plan.Users] = 99
	r.Ladder()[0].Limits[plan.Users] = 98
	if r.For("a").Cap(plan.Users) != 3 {
		t.Error("the registry shares its maps")
	}
	if d := r.Describe("a"); d.Label != "A" {
		t.Errorf("described %+v", d)
	}
}

// An override replaces the band's value for one limit or feature until its
// end, and is ignored from then on with nothing run: resolution is the
// band's value, then the override in force.
func TestOverridesResolveAfterTheBand(t *testing.T) {
	later, earlier := time.Now().Add(time.Hour), time.Now().Add(-time.Minute)
	deal := plan.Entitlements{Band: "team", Overrides: []plan.Override{
		{Limit: plan.Users, Cap: 75, EndsAt: &later},
		{Feature: plan.SCIM, Allowed: true},
		{Feature: plan.AuditExport, Allowed: true, EndsAt: &earlier},
	}}
	if deal.Cap(plan.Users) != 75 || deal.CheckUsers(74) != nil {
		t.Errorf("raised cap: %d %v", deal.Cap(plan.Users), deal.CheckUsers(74))
	}
	r, ok := plan.AsRefusal(deal.CheckUsers(75))
	if !ok || r.Plan != "team" || r.Limit != "users" || r.Required != "business" || !strings.Contains(r.Message, "agreement allows 75 users") {
		t.Errorf("past the deal's cap: %+v", r)
	}
	if err := deal.CheckFeature(plan.SCIM); err != nil {
		t.Errorf("SCIM granted: %v", err)
	}
	if r, ok := plan.AsRefusal(deal.CheckFeature(plan.AuditExport)); !ok || r.Required != "enterprise" {
		t.Errorf("an ended grant still applies: %+v", r)
	}
	d := deal.Describe()
	if d.Limits["users"] != 75 || strings.Join(d.Features, ",") != "api_access,scim" || len(d.Overrides) != 2 {
		t.Errorf("described: %+v", d)
	}

	// Lowered and taken away, under a band that would allow both.
	tight := plan.Entitlements{Band: "enterprise", Overrides: []plan.Override{{Limit: plan.Users, Cap: 5}, {Feature: plan.SCIM, Allowed: false}}}
	if r, ok := plan.AsRefusal(tight.CheckUsers(5)); !ok || r.Required != "" {
		t.Errorf("lowered cap: %+v", r)
	}
	if r, ok := plan.AsRefusal(tight.CheckFeature(plan.SCIM)); !ok || !strings.Contains(r.Message, "agreement does not include SCIM") {
		t.Errorf("taken away: %+v", r)
	}
	// An ended override is the band again; an unlimited one lifts the cap.
	ended := plan.Entitlements{Band: "free", Overrides: []plan.Override{{Limit: plan.Users, Cap: 500, EndsAt: &earlier}}}
	if r, ok := plan.AsRefusal(ended.CheckUsers(10)); !ok || r.Required != "team" {
		t.Errorf("ended: %+v", r)
	}
	lifted := plan.Entitlements{Band: "free", Overrides: []plan.Override{{Limit: plan.Users, Cap: plan.Unlimited}}}
	if err := lifted.CheckUsers(100000); err != nil {
		t.Errorf("lifted: %v", err)
	}

	// Only a registered limit or feature can be overridden.
	for _, o := range []plan.Override{{Limit: "seats", Cap: 1}, {Feature: "teleport", Allowed: true}, {}, {Limit: plan.Users, Feature: plan.SCIM}, {Limit: plan.Users, Cap: -1}} {
		if plan.Default.CheckOverride(o) == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}
