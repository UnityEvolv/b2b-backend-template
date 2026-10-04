// Package product is everything the example product declares to the
// template, in one place: its service and schema, its plan limit, its
// permission group, its notification category, its data owner entry, its
// live event type, its storage purpose, its rate-limit rule and its
// onboarding step.
//
// Some of it is registered in this product's own processes (Register, and
// the package variables below). The rest is for the template's services,
// which run unchanged and learn it from their configuration: Env renders
// PLANS, PERMISSION_GROUPS, NOTIFICATION_CATEGORIES, DATA_OWNERS and
// ONBOARDING_STEPS from the same values, so what a deployment sets is
// exactly what the code declares. A product that builds its own copy of one of those services registers the
// same values in code instead (authz.Default.Register(PermissionGroup), and
// so on).
package product

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
)

// Name is the service's name: its schema, its role (svc_projects), the name
// its service tokens carry, and its data owner entry.
const Name = "projects"

// Service is the projects service in pkg/db: its own schema and its own
// migrations, kept beside it.
var Service = db.Service{Name: Name, Schema: "projects", Migrations: migrations.FS}

// Projects is the plan limit: how many projects an org may have.
const Projects plan.Limit = "projects"

// ProjectsLimit is the limit as the registry lists it, with the plural noun
// a refusal and the plans page use.
var ProjectsLimit = plan.LimitSpec{Key: Projects, Label: "projects"}

// Caps is the projects cap on each band of the template's ladder. A band
// left out (enterprise) has no cap.
var Caps = map[plan.Band]int{"free": 3, "team": 25, "business": 100}

// Permission is the permission group every write checks.
const Permission authz.Permission = "projects"

// PermissionGroup is the group as the authorization service lists it:
// Admins hold it until an Owner decides otherwise.
var PermissionGroup = authz.Group{
	Key:         Permission,
	Label:       "Projects",
	Description: "Create, rename and delete projects, share them with people and set their covers.",
	Default:     []authz.Role{authz.Admin},
}

// Shared is the notification category and the kind of the one event this
// product emits: a project was shared with someone.
const Shared = "project_shared"

// SharedCategory is how the notification service routes it: to the feed and
// push by default, the digest if the person wants, held for quiet hours.
var SharedCategory = notifycat.Category{
	ID:          Shared,
	Label:       "Shared projects",
	Description: "When someone shares a project with you.",
	Audience:    notifycat.Member,
	Default:     notifycat.Channels{InApp: true, Push: true},
	QuietHours:  true,
	Copy: map[string]notifycat.Copy{
		Shared: {Title: "{by|Someone} shared {project|a project} with you", Line: "Open it to see what is in it.", Many: "{count} projects were shared with you"},
	},
}

// Owner is the data owner entry: projects are in the org export and the
// person's, go when the org is purged, and a member's shares are forgotten
// when their account is deleted. Its URL is PROJECTS_URL.
var Owner = dataowner.Owner{Name: Name, Export: true, Purge: true, Erase: true}

// SharedEvent is the live-session event its open sessions get when a
// project is shared with someone.
const SharedEvent livebus.Type = "project.shared"

// CoverImage is the storage purpose of a project's cover.
var CoverImage = storage.Default.Register(storage.Purpose{Name: "project-cover",
	ContentTypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxBytes: 2 << 20})

// CreateRule is the rate limit on creating projects, per membership, on
// top of the plan's cap.
var CreateRule = ratelimit.Default.Register(ratelimit.Rule{Name: "project-create", Limit: 20, Window: time.Minute}, ratelimit.PerMembership)

// FirstProject is the onboarding step this product adds to the checklist,
// after the core's: done once the org has a project. This service answers
// it (GET /v1/internal/organizations/{org_id}/onboarding/create_project),
// found by PROJECTS_URL.
const FirstProject = "create_project"

// OnboardingStep is the step as the organization service lists it: done
// in the product's own web app (b2b-frontend-template/examples/projects).
var OnboardingStep = onboarding.Step{ID: FirstProject, Label: "Create your first project", Href: "/projects/new", App: "projects", Service: Name}

var once sync.Once

// Register declares the product to the registries its own processes read:
// the service and schema (pkg/db), the plan limit on the template's ladder
// (pkg/plan) and the live event type (pkg/livebus). Every command of the
// product calls it first; it runs once.
func Register() {
	once.Do(func() {
		db.Default.Register(Service)
		plan.Default.RegisterLimit(ProjectsLimit)
		plan.Default.SetBands(Bands())
		livebus.Default.Register(SharedEvent, "A project was shared with someone.")
	})
}

// Bands is the template's ladder with the projects cap on each band.
func Bands() []plan.BandSpec {
	bands := plan.DefaultBands()
	for i, b := range bands {
		if c, ok := Caps[b.Name]; ok {
			limits := map[plan.Limit]int{}
			for l, v := range b.Limits {
				limits[l] = v
			}
			limits[Projects] = c
			bands[i].Limits = limits
		}
	}
	return bands
}

// Plans is the plan configuration: the projects limit, and the template's
// ladder with the projects cap on each band. The template's services read it
// from PLANS; this product's own processes register the same in Register.
func Plans() plan.Config {
	return plan.Config{Limits: []plan.LimitSpec{ProjectsLimit}, Bands: Bands()}
}

// Env is the configuration the template's services need to know this
// product: the setting's name and its JSON value, from the values above.
// PROJECTS_URL, the service's own address, is the deployment's.
func Env() map[string]string {
	group := map[string]any{
		"key": PermissionGroup.Key, "label": PermissionGroup.Label,
		"description": PermissionGroup.Description, "default": PermissionGroup.Default,
	}
	category := map[string]any{
		"id": SharedCategory.ID, "label": SharedCategory.Label, "description": SharedCategory.Description,
		"audience": SharedCategory.Audience, "default": SharedCategory.Default,
		"quiet_hours": SharedCategory.QuietHours, "batched": SharedCategory.Batched, "copy": SharedCategory.Copy,
	}
	return map[string]string{
		"PLANS":                   mustJSON(Plans()),
		"PERMISSION_GROUPS":       mustJSON([]any{group}),
		"NOTIFICATION_CATEGORIES": mustJSON([]any{category}),
		"DATA_OWNERS":             mustJSON([]dataowner.Owner{Owner}),
		"ONBOARDING_STEPS":        mustJSON([]onboarding.Step{OnboardingStep}),
	}
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
