// Package notifycat is the notification categories: what a
// notification can be about, the rows of the preferences grid. Each is
// registered with who it is for, where it goes until the person or their
// org decides otherwise, whether quiet hours hold it, and its words. The
// notification service validates every event, preference and feed entry
// against the registry; nothing else in the platform, the database and the
// API contract included, lists the categories.
//
// The template registers security, membership, billing and admin notices. A
// product registers its own ("project_shared") with Default.Register in the
// notification service's main, or through NOTIFICATION_CATEGORIES when it
// runs that service unchanged (Parse), and emits events naming it.
package notifycat

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Audience is who a category is for.
type Audience string

const (
	// Member: anyone in the org, about their own work or account. Links
	// open in the main app.
	Member Audience = "member"
	// Admin: the people who run the org. Links open in the admin app.
	Admin Audience = "admin"
)

// Channel is one way a notification reaches a person.
type Channel string

const (
	// Feed is the in-app feed (in_app on the wire).
	Feed Channel = "in_app"
	// Push is a push to the person's phones and browsers.
	Push Channel = "push"
	// Email is an email at once.
	Email Channel = "email"
	// Digest is a line in the daily digest email.
	Digest Channel = "digest"
)

// AllChannels is every channel, in the grid's order.
var AllChannels = []Channel{Feed, Push, Email, Digest}

// Channels is where one category goes.
type Channels struct {
	InApp  bool `json:"in_app"`
	Push   bool `json:"push"`
	Email  bool `json:"email"`
	Digest bool `json:"digest"`
}

// Has reports whether c includes ch.
func (c Channels) Has(ch Channel) bool {
	switch ch {
	case Feed:
		return c.InApp
	case Push:
		return c.Push
	case Email:
		return c.Email
	case Digest:
		return c.Digest
	}
	return false
}

// Only is c with every channel not in allowed turned off.
func (c Channels) Only(allowed []Channel) Channels {
	return Channels{
		InApp:  c.InApp && slices.Contains(allowed, Feed),
		Push:   c.Push && slices.Contains(allowed, Push),
		Email:  c.Email && slices.Contains(allowed, Email),
		Digest: c.Digest && slices.Contains(allowed, Digest),
	}
}

// Copy is what a push or an email says for one kind of event: a title and a
// line, with {key} replaced by the event's data (and {key|fallback} when it
// may be missing), and Many the title for a batch of {count}.
type Copy struct {
	Title string `json:"title"`
	Line  string `json:"line"`
	Many  string `json:"many,omitempty"`
}

// Category is one registered category.
type Category struct {
	// ID is the category's name in events, preferences and the feed:
	// lower case, a letter first, letters, digits and underscores.
	ID string
	// Label is what the preferences page calls it: "Security".
	Label string
	// Description is what it covers, for the preferences page.
	Description string
	Audience    Audience
	// Default is where it goes for someone who has not chosen, in an org
	// that has not chosen either.
	Default Channels
	// Channels is where it may go at all; a choice outside it is ignored.
	// Empty is every channel.
	Channels []Channel
	// QuietHours: push and email wait for the end of the person's quiet
	// hours. Off for what is useless later.
	QuietHours bool
	// Batched: events with the same group within a few minutes are one feed
	// entry and one push.
	Batched bool
	// Platforms is the push platforms it goes to (web, android, ios);
	// empty is every one.
	Platforms []string
	// Copy is the words for each kind of event, and Copy[""] for any other
	// kind. With neither, an event's own data.heading and data.line.
	Copy map[string]Copy
}

// Allowed is where c may go.
func (c Category) Allowed() []Channel {
	if len(c.Channels) == 0 {
		return slices.Clone(AllChannels)
	}
	return slices.Clone(c.Channels)
}

// PushesTo reports whether c's pushes go to a device on platform.
func (c Category) PushesTo(platform string) bool {
	return len(c.Platforms) == 0 || slices.Contains(c.Platforms, platform)
}

// DigestToken is the name an unsubscribe link for the digest carries in
// place of a category; no category may be called it.
const DigestToken = "digest"

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,59}$`)

func check(c Category) error {
	if !idPattern.MatchString(c.ID) || c.ID == DigestToken {
		return fmt.Errorf("notifycat: %q cannot be a category", c.ID)
	}
	if c.Audience != Member && c.Audience != Admin {
		return fmt.Errorf("notifycat: category %q is for %q, not member or admin", c.ID, c.Audience)
	}
	for _, ch := range c.Channels {
		if !slices.Contains(AllChannels, ch) {
			return fmt.Errorf("notifycat: category %q names channel %q", c.ID, ch)
		}
	}
	if c.Default != c.Default.Only(c.Allowed()) {
		return fmt.Errorf("notifycat: category %q defaults to a channel it may not use", c.ID)
	}
	return nil
}

// Registry is the categories: the template's and the ones a product
// registers. Safe for concurrent use; registration is expected at start,
// before requests.
type Registry struct {
	mu         sync.RWMutex
	categories []Category
}

// The template's own categories.
const (
	// Security: a new sign-in to the person's account, their two-step
	// verification changed. Everywhere, and never held for quiet hours.
	Security = "security"
	// Membership: the person was invited somewhere, their role changed.
	Membership = "membership"
	// Billing: the plan, trials, payments. For the org's billing people.
	Billing = "billing"
	// AdminNotices: what an org's admins must know about the org, such as
	// a directory sync that halted.
	AdminNotices = "admin_notices"
)

// New is a registry with the template's own categories.
func New() *Registry {
	r := &Registry{}
	r.Register(Category{ID: Security, Label: "Security", Audience: Member,
		Description: "New sign-ins to your account and changes to how you sign in.",
		Default:     Channels{InApp: true, Push: true, Email: true},
		Copy: map[string]Copy{
			"new_sign_in": {Title: "New sign-in to your account", Line: "From {where|a new device}. If it was not you, change your password and sign out everywhere."},
			"mfa_changed": {Title: "Two-step verification changed", Line: "{by|Someone} changed how you sign in. If it was not you, contact your admin."},
			"test":        {Title: "Notifications are working", Line: "This is the test you asked for."},
		}})
	r.Register(Category{ID: Membership, Label: "Membership", Audience: Member, QuietHours: true,
		Description: "Invitations, and changes to your role.",
		Default:     Channels{InApp: true, Email: true},
		Copy: map[string]Copy{
			"invited":      {Title: "You were invited to {where|an organization}", Line: "{by|Someone} invited you. Open the invitation to join."},
			"role_changed": {Title: "Your role is now {role|changed}", Line: "{by|An admin} changed it."},
		}})
	r.Register(Category{ID: Billing, Label: "Billing", Audience: Admin, QuietHours: true,
		Description: "The plan, trials and payments.",
		Default:     Channels{InApp: true, Email: true}})
	r.Register(Category{ID: AdminNotices, Label: "Admin notices", Audience: Admin, QuietHours: true,
		Description: "What needs an admin's attention, such as a directory sync that stopped.",
		Default:     Channels{InApp: true, Email: true}})
	return r
}

// Default is the registry the notification service reads. A product adds
// its categories at start; the template's own are in it until then.
var Default = New()

// Register adds a category, replacing one with the same id. One with a bad
// id or audience, or a default on a channel it may not use, panics: it is a
// programming error at start, not a request.
func (r *Registry) Register(c Category) {
	if err := check(c); err != nil {
		panic(err.Error())
	}
	if c.Label == "" {
		c.Label = c.ID
	}
	c.Channels = slices.Clone(c.Channels)
	c.Platforms = slices.Clone(c.Platforms)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.categories {
		if x.ID == c.ID {
			r.categories[i] = c
			return
		}
	}
	r.categories = append(r.categories, c)
}

// Parse reads categories from configuration, for a product that runs the
// notification service unchanged: a JSON list such as
//
//	[{"id":"project_shared","label":"Shared projects","audience":"member",
//	  "default":{"in_app":true,"push":true,"digest":true},"quiet_hours":true,
//	  "copy":{"project_shared":{"title":"{by|Someone} shared {project|a project} with you","line":"Open it to see."}}}]
//
// Each is checked as Register would; empty is none.
func Parse(s string) ([]Category, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var in []struct {
		ID          string          `json:"id"`
		Label       string          `json:"label"`
		Description string          `json:"description"`
		Audience    Audience        `json:"audience"`
		Default     Channels        `json:"default"`
		Channels    []Channel       `json:"channels"`
		QuietHours  bool            `json:"quiet_hours"`
		Batched     bool            `json:"batched"`
		Platforms   []string        `json:"platforms"`
		Copy        map[string]Copy `json:"copy"`
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("notifycat: categories: %w", err)
	}
	out := make([]Category, 0, len(in))
	for _, x := range in {
		c := Category(x)
		if err := check(c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Load registers every category in s, NOTIFICATION_CATEGORIES' value.
func (r *Registry) Load(s string) error {
	cs, err := Parse(s)
	if err != nil {
		return err
	}
	for _, c := range cs {
		r.Register(c)
	}
	return nil
}

// Categories is every registered category, in registration order.
func (r *Registry) Categories() []Category {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.categories)
}

// Get is the category with id.
func (r *Registry) Get(id string) (Category, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.categories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// Valid reports whether id is registered.
func (r *Registry) Valid(id string) bool {
	_, ok := r.Get(id)
	return ok
}

// Resolve is the channels for every category: the person's choice, else
// the org's default for new members, else the category's, each limited to
// where the category may go. person and org are stored grids, category id
// => channels; ids no longer registered are ignored.
func (r *Registry) Resolve(person, org []byte) map[string]Channels {
	var mine, theirs map[string]Channels
	_ = json.Unmarshal(person, &mine)
	_ = json.Unmarshal(org, &theirs)
	cs := r.Categories()
	out := make(map[string]Channels, len(cs))
	for _, c := range cs {
		ch := c.Default
		if v, ok := theirs[c.ID]; ok {
			ch = v
		}
		if v, ok := mine[c.ID]; ok {
			ch = v
		}
		out[c.ID] = ch.Only(c.Allowed())
	}
	return out
}

// Words is what a push or an email says for an event of kind in category:
// its copy, filled in from data. count above one is a batch.
func (r *Registry) Words(category, kind string, data map[string]any, count int) (string, string) {
	c, _ := r.Get(category)
	cp, ok := c.Copy[kind]
	if !ok {
		cp, ok = c.Copy[""]
	}
	if !ok {
		cp = Copy{Title: "{heading|Something needs your attention}", Line: "{line|Open the app to see it.}"}
	}
	title := cp.Title
	if count > 1 && cp.Many != "" {
		title = cp.Many
	}
	return Expand(title, data, count), Expand(cp.Line, data, count)
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)(?:\|([^}]*))?\}`)

// Expand replaces each {key} in s with data[key], {key|fallback} with the
// fallback when data has none, and {count} with count.
func Expand(s string, data map[string]any, count int) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		parts := placeholder.FindStringSubmatch(m)
		key, fallback := parts[1], parts[2]
		if key == "count" {
			return strconv.Itoa(count)
		}
		switch v := data[key].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		case float64, int, int64, bool:
			return fmt.Sprint(v)
		}
		return fallback
	})
}
