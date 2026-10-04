// Package onboarding is the registry of first-run steps a new org is guided
// through (docs/onboarding.md): the core's (verify the domain, invite
// teammates, set up single sign-on, choose a plan) and a product's
// ("create your first project").
//
// A step is never a stored flag. Whether it is done is asked, at the moment
// the checklist is read, of the service that holds the data that says so:
//
//	GET <service>/v1/internal/organizations/{org_id}/onboarding/{step_id}
//	-> 200 {"done": true}
//
// answered to the organization service's own token only. The organization
// service serves the checklist and asks every step's service at once, each
// within a short timeout; one that does not answer leaves its step unknown,
// never the checklist failed. Only an org's dismissals are stored.
//
// The template registers its own four. A product adds its steps in code with
// Default.Register, or, running the template's organization service
// unchanged, through ONBOARDING_STEPS (Parse), each naming the service that
// answers it: a data owner's name, located by <NAME>_URL like one
// (pkg/dataowner), or with its own url.
package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Caller is the only service that asks whether a step is done.
const Caller = "organization"

// Step is one thing a new org is guided to do.
type Step struct {
	// ID is stable, lower case: "verify_domain", "create_project".
	ID string `json:"id"`
	// Label is what the checklist says: "Verify your domain".
	Label string `json:"label"`
	// Href is where in the app the step is done: a path in App.
	Href string `json:"href"`
	// App is the web app Href is in, by name (APP_NAMES); the admin app
	// when empty.
	App string `json:"app,omitempty"`
	// Service answers whether the step is done for an org, at
	// /v1/internal/organizations/{org_id}/onboarding/{id}: a service the
	// platform knows (a template service, or a data owner).
	Service string `json:"service"`
	// URL is that service's base URL. Empty, it is read from <SERVICE>_URL
	// (Locate), as a data owner's is.
	URL string `json:"url,omitempty"`
}

// DefaultApp is the app a step is in when it names none.
const DefaultApp = "admin"

// URLVar is the setting the service's URL is read from when URL is empty.
func (s Step) URLVar() string {
	return strings.ToUpper(strings.ReplaceAll(s.Service, "-", "_")) + "_URL"
}

// The core's steps.
const (
	// VerifyDomain is done when the org has a proven domain: its signup
	// mailbox, or a TXT record. Answered by the organization service.
	VerifyDomain = "verify_domain"
	// InviteTeammates is done when the org has sent at least one invite,
	// whatever became of it, or has a second active member however they
	// came. Answered by the identity service.
	InviteTeammates = "invite_teammates"
	// SetUpSSO is done when the org's identity provider is saved and
	// active. Answered by the identity service.
	SetUpSSO = "set_up_sso"
	// ChoosePlan is done while the org is on a band above the ladder's
	// lowest: paid, contractual, or trialing one (a trial moves the band).
	// Back on the lowest band, it is not done. Answered by the organization
	// service.
	ChoosePlan = "choose_plan"
)

var (
	idShape   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,50}$`)
	nameShape = regexp.MustCompile(`^[a-z][a-z0-9-]{0,50}$`)
)

// Registry is the steps, in the order the checklist shows them: the core's
// and a product's. Safe for concurrent use; registration is expected at
// start, before requests.
type Registry struct {
	mu    sync.RWMutex
	steps []Step
}

// New is a registry with the core's four steps.
func New() *Registry {
	r := &Registry{}
	for _, s := range []Step{
		{ID: VerifyDomain, Label: "Verify your domain", Href: "/settings", Service: "organization"},
		{ID: InviteTeammates, Label: "Invite your teammates", Href: "/users/invite", Service: "identity"},
		{ID: SetUpSSO, Label: "Set up single sign-on", Href: "/sso", Service: "identity"},
		{ID: ChoosePlan, Label: "Choose a plan", Href: "/billing", Service: "organization"},
	} {
		r.Register(s)
	}
	return r
}

// Default is the registry the organization service reads. A product adds
// its steps at start, in code or from ONBOARDING_STEPS.
var Default = New()

// Register adds a step at the end, or replaces one with the same id in
// place. A step that is malformed panics: it is a programming error at
// start, not a request.
func (r *Registry) Register(s Step) {
	if err := check(s); err != nil {
		panic(err.Error())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.steps {
		if x.ID == s.ID {
			r.steps[i] = s
			return
		}
	}
	r.steps = append(r.steps, s)
}

func check(s Step) error {
	switch {
	case !idShape.MatchString(s.ID):
		return fmt.Errorf("onboarding: %q cannot be a step id", s.ID)
	case strings.TrimSpace(s.Label) == "" || len(s.Label) > 100:
		return fmt.Errorf("onboarding: step %q needs a label of at most 100 characters", s.ID)
	case !strings.HasPrefix(s.Href, "/") || strings.HasPrefix(s.Href, "//") || len(s.Href) > 200:
		return fmt.Errorf("onboarding: step %q needs a path in its app as its href", s.ID)
	case s.App != "" && !nameShape.MatchString(s.App):
		return fmt.Errorf("onboarding: step %q names %q as its app", s.ID, s.App)
	case !nameShape.MatchString(s.Service):
		return fmt.Errorf("onboarding: step %q needs the service that answers it", s.ID)
	}
	return nil
}

// Parse reads steps from configuration, for a product that runs the
// template's organization service unchanged: a JSON list such as
//
//	[{"id":"create_project","label":"Create your first project","href":"/projects","service":"projects"}]
//
// Each is checked as Register would; empty is none.
func Parse(s string) ([]Step, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var in []Step
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("onboarding: steps: %w", err)
	}
	for _, x := range in {
		if err := check(x); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// Load registers every step in s, ONBOARDING_STEPS' value, in r.
func (r *Registry) Load(s string) error {
	steps, err := Parse(s)
	if err != nil {
		return err
	}
	for _, x := range steps {
		r.Register(x)
	}
	return nil
}

// Steps is every step, in order, each with its app filled in.
func (r *Registry) Steps() []Step {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := slices.Clone(r.steps)
	for i := range out {
		if out[i].App == "" {
			out[i].App = DefaultApp
		}
	}
	return out
}

// Step is the step with id.
func (r *Registry) Step(id string) (Step, bool) {
	for _, s := range r.Steps() {
		if s.ID == id {
			return s, true
		}
	}
	return Step{}, false
}

// Locate fills in the URL of every step answered by a service other than
// self: its own, or the value of its URLVar from lookup. One with neither is
// an error naming the setting, so a misconfigured deploy fails at start.
func (r *Registry) Locate(lookup func(string) string, self string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var missing []string
	for i, s := range r.steps {
		if s.Service == self || s.URL != "" {
			continue
		}
		r.steps[i].URL = strings.TrimSpace(lookup(s.URLVar()))
		if r.steps[i].URL == "" && !slices.Contains(missing, s.URLVar()) {
			missing = append(missing, s.URLVar())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("onboarding: %s not set", strings.Join(missing, ", "))
	}
	return nil
}

// Status is a service's answer for one step.
type Status struct {
	Done bool `json:"done"`
}

// Path is where a service answers for step in org.
func Path(org uuid.UUID, step string) string {
	return "/v1/internal/organizations/" + org.String() + "/onboarding/" + step
}

// Checker asks a step's service whether the step is done for an org.
type Checker interface {
	Done(ctx context.Context, s Step, org uuid.UUID) (bool, error)
}

// Timeout is how long one step's service has to answer before the step is
// shown as unknown.
const Timeout = 2 * time.Second

type client struct {
	tokens auth.TokenSource
	http   *http.Client
}

// NewClient is a Checker over HTTP, as this service (tokens), each call
// bounded by Timeout.
func NewClient(tokens auth.TokenSource, h *http.Client) Checker {
	if h == nil {
		h = &http.Client{Timeout: Timeout}
	}
	return &client{tokens: tokens, http: h}
}

func (c *client) Done(ctx context.Context, s Step, org uuid.UUID) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.URL, "/")+Path(org, s.ID), nil)
	if err != nil {
		return false, err
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return false, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("onboarding: %s: %w", s.Service, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("onboarding: %s answered %d for %s", s.Service, resp.StatusCode, s.ID)
	}
	var st Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&st); err != nil {
		return false, fmt.Errorf("onboarding: %s: %w", s.Service, err)
	}
	return st.Done, nil
}
