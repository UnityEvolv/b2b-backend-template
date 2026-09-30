package product_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
)

// What a deployment sets on the template's services is exactly what the
// product declares in code: each value of Env parses, with the template's
// own parser, back to the same declaration.
func TestTheEnvIsTheCode(t *testing.T) {
	env := product.Env()

	groups, err := authz.ParseGroups(env["PERMISSION_GROUPS"])
	if err != nil || len(groups) != 1 || !reflect.DeepEqual(groups[0], product.PermissionGroup) {
		t.Errorf("PERMISSION_GROUPS parses to %+v (%v), want %+v", groups, err, product.PermissionGroup)
	}
	categories, err := notifycat.Parse(env["NOTIFICATION_CATEGORIES"])
	if err != nil || len(categories) != 1 || !reflect.DeepEqual(categories[0], product.SharedCategory) {
		t.Errorf("NOTIFICATION_CATEGORIES parses to %+v (%v), want %+v", categories, err, product.SharedCategory)
	}
	owners, err := dataowner.Parse(env["DATA_OWNERS"])
	if err != nil || len(owners) != 1 || owners[0] != product.Owner {
		t.Errorf("DATA_OWNERS parses to %+v (%v), want %+v", owners, err, product.Owner)
	}
	plans, err := plan.ParseConfig(env["PLANS"])
	if err != nil || !reflect.DeepEqual(plans, product.Plans()) {
		t.Errorf("PLANS parses to %+v (%v), want %+v", plans, err, product.Plans())
	}
	// Loaded as the organization, user and billing services load it, it is
	// the ladder the product's own process registers.
	loaded := plan.New()
	if err := loaded.Load(env["PLANS"]); err != nil {
		t.Fatalf("PLANS: %v", err)
	}
	for _, b := range product.Bands() {
		if got := loaded.Describe(b.Name); got.Limits[string(product.Projects)] != b.Cap(product.Projects) || got.Limits["users"] != b.Cap(plan.Users) {
			t.Errorf("%s from PLANS: %+v", b.Name, got)
		}
	}
	if product.Owner.URLVar() != "PROJECTS_URL" {
		t.Errorf("its URL is read from %s", product.Owner.URLVar())
	}
}

// A product that builds its own authorization or notification service
// registers the same values in code, and gets what the env gives the
// unchanged one: Admins hold projects by default, the category routes to the
// feed and push.
func TestTheCodePathRegistersTheSame(t *testing.T) {
	groups := authz.New()
	groups.Register(product.PermissionGroup)
	if d := groups.Defaults(); !slices.Contains(d.Admin, product.Permission) || slices.Contains(d.BillingAdmin, product.Permission) {
		t.Errorf("defaults %+v", d)
	}
	if !slices.Contains(groups.Effective(authz.Owner, groups.Defaults()), product.Permission) {
		t.Error("the Owner does not have projects")
	}
	if slices.Contains(groups.Effective(authz.User, groups.Defaults()), product.Permission) {
		t.Error("a User has projects")
	}

	cats := notifycat.New()
	cats.Register(product.SharedCategory)
	if !cats.Valid(product.Shared) {
		t.Fatal("the category is not valid once registered")
	}
	title, _ := cats.Words(product.Shared, product.Shared, map[string]any{"by": "Ada", "project": "Apollo"}, 1)
	if title != "Ada shared Apollo with you" {
		t.Errorf("title %q", title)
	}

	owners := dataowner.New()
	owners.Register(product.Owner)
	if !slices.ContainsFunc(owners.Erasers(), func(o dataowner.Owner) bool { return o.Name == product.Name }) {
		t.Error("not an eraser")
	}
	purgers := owners.Purgers()
	if purgers[len(purgers)-1].Name != "audit" {
		t.Errorf("audit is no longer purged last: %v", purgers)
	}
}

// Register puts the service, its limit and its event type in the registries
// its own processes read, and the storage purpose and rate-limit rule are
// there from the start.
func TestRegister(t *testing.T) {
	product.Register()
	product.Register() // once

	s, ok := db.ServiceByName(product.Name)
	if !ok || s.Schema != "projects" || s.Role() != "svc_projects" || s.Migrations == nil {
		t.Errorf("pkg/db: %+v %v", s, ok)
	}
	if !livebus.Default.Known(product.SharedEvent) {
		t.Error("the live event type is not registered")
	}
	if _, ok := storage.Default.Lookup("project-cover"); !ok {
		t.Error("the cover purpose is not registered")
	}
	if r, ok := ratelimit.Default.Lookup("project-create"); !ok || r.Per != ratelimit.PerMembership || r.Limit != 20 {
		t.Errorf("the create rule: %+v %v", r, ok)
	}

	// The template's ladder, each band keeping its user cap, with a
	// projects cap on each but enterprise.
	if got := plan.Bands(); !slices.Equal(got, []plan.Band{"free", "team", "business", "enterprise"}) {
		t.Errorf("bands %v", got)
	}
	for _, b := range plan.DefaultBands() {
		if got := plan.For(b.Name).Cap(plan.Users); got != b.Cap(plan.Users) {
			t.Errorf("%s: users cap %d, want %d", b.Name, got, b.Cap(plan.Users))
		}
	}
	if plan.For("enterprise").Cap(product.Projects) != plan.Unlimited {
		t.Error("enterprise is capped")
	}

	// At the cap, refused in the envelope's terms, naming the next plan.
	if err := plan.CheckLimit("free", product.Projects, 2); err != nil {
		t.Errorf("under the cap: %v", err)
	}
	r, ok := plan.AsRefusal(plan.CheckLimit("free", product.Projects, 3))
	if !ok || !reflect.DeepEqual(r.Fields(), map[string]string{"plan": "free", "limit": "projects", "required_plan": "team"}) {
		t.Errorf("at the cap: %+v", r)
	}
	if plan.Code != "plan.limit_reached" {
		t.Errorf("code %s", plan.Code)
	}

	// The purpose decides what a cover may be.
	for _, c := range []struct {
		contentType string
		size        int64
		ok          bool
	}{
		{"image/png", 1024, true}, {"image/webp", 2 << 20, true},
		{"application/pdf", 1024, false}, {"image/png", 2<<20 + 1, false}, {"image/png", 0, false},
	} {
		if err := product.CoverImage.Validate(c.contentType, c.size); (err == nil) != c.ok {
			t.Errorf("%s of %d: %v", c.contentType, c.size, err)
		}
	}
}

// The example reaches the template only through pkg/: it imports no
// template service, as no service imports another.
func TestImportsNoTemplateService(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "list", "-deps", "-json", "./examples/projects/...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var pkg struct{ ImportPath string }
		if err := dec.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(pkg.ImportPath, "github.com/UnityEvolv/b2b-backend-template/services/") {
			t.Errorf("the example depends on %s; call the service's API instead", pkg.ImportPath)
		}
	}
}
