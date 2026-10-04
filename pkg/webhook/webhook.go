// Package webhook is what the template and a product share about outbound
// webhooks: the event types a customer may subscribe to, the call a
// service makes to send one, and the signature every delivery carries.
// The webhooks service (services/webhooks) owns the endpoints, the
// deliveries and their retries; docs/webhooks.md is the whole picture.
//
// The event types are a registry. The core registers the membership events
// it derives from the audit log (member.added, member.removed,
// member.role_changed); a product registers its own in the webhooks
// service's process (Default.Register) or, running it unchanged, through
// WEBHOOK_EVENTS (Parse). A product's service then sends one with a single
// call, as itself:
//
//	err := webhooks.Emit(ctx, orgID, webhook.Message{Type: "project.created",
//	    Data: map[string]any{"project_id": id}})
//
// Payloads carry ids, never a name or an email: CheckData refuses one that
// looks like it does.
package webhook

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Type is an event type: dotted, lower case, such as member.added.
type Type string

// The core's event types, derived from the audit log (FromAudit).
const (
	// MemberAdded: a membership was created, or a removed one made active
	// again. Data: membership_id, user_id, role, and source or reason.
	MemberAdded Type = "member.added"
	// MemberRemoved: a membership stopped being active: deactivated,
	// suspended, left, or its person's account deleted. Data:
	// membership_id, user_id, reason.
	MemberRemoved Type = "member.removed"
	// MemberRoleChanged: a membership's role changed. Data: membership_id,
	// from, to.
	MemberRoleChanged Type = "member.role_changed"
)

// Test is the event an admin sends to one endpoint to try it. It is not a
// type anyone subscribes to: it goes to the endpoint asked, whatever its
// filter.
const Test Type = "webhook.test"

// EventType is one registered type, as the admin UI lists it.
type EventType struct {
	Type        Type   `json:"type"`
	Description string `json:"description"`
}

var typeName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Registry is the event types a customer may subscribe to: the core's and
// the ones a product registers. Safe for concurrent use; registration is
// expected at start, before requests.
type Registry struct {
	mu    sync.RWMutex
	types []EventType
}

// New is a registry with the core's types.
func New() *Registry {
	r := &Registry{}
	r.Register(EventType{Type: MemberAdded, Description: "Someone joined the organization, or was made active again."})
	r.Register(EventType{Type: MemberRemoved, Description: "Someone was deactivated or suspended, left, or deleted their account."})
	r.Register(EventType{Type: MemberRoleChanged, Description: "Someone's role changed."})
	return r
}

// Default is the registry the webhooks service reads. A product adds its
// types at start; the core's are in it until then.
var Default = New()

// Register adds a type, replacing one with the same name. A name that is
// not dotted lower case, or is the test event's, panics: it is a
// programming error at start, not a request.
func (r *Registry) Register(t EventType) {
	if err := check(t); err != nil {
		panic(err.Error())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.types {
		if x.Type == t.Type {
			r.types[i] = t
			return
		}
	}
	r.types = append(r.types, t)
}

func check(t EventType) error {
	if !typeName.MatchString(string(t.Type)) || t.Type == Test {
		return fmt.Errorf("webhook: %q cannot be an event type", t.Type)
	}
	return nil
}

// Known reports whether t is registered.
func (r *Registry) Known(t Type) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.ContainsFunc(r.types, func(x EventType) bool { return x.Type == t })
}

// Types is every registered type, in registration order.
func (r *Registry) Types() []EventType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.types)
}

// Parse reads event types from configuration, for a product that runs the
// webhooks service unchanged: a JSON list such as
//
//	[{"type":"project.created","description":"A project was created."}]
//
// Each is checked as Register would; empty is none.
func Parse(s string) ([]EventType, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var in []EventType
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("webhook: event types: %w", err)
	}
	for _, t := range in {
		if err := check(t); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// Load registers every type in s, WEBHOOK_EVENTS' value, in r.
func (r *Registry) Load(s string) error {
	types, err := Parse(s)
	if err != nil {
		return err
	}
	for _, t := range types {
		r.Register(t)
	}
	return nil
}

// MaxData is the largest event data, as JSON.
const MaxData = 16 * 1024

// personal are keys that name a person rather than identify one.
var personal = map[string]bool{
	"email": true, "email_address": true, "name": true, "first_name": true, "last_name": true,
	"display_name": true, "full_name": true, "given_name": true, "family_name": true, "phone": true, "phone_number": true,
}

var emailShape = regexp.MustCompile(`[^\s@]+@[^\s@]+\.[^\s@]+`)

// CheckData refuses event data that is too large or looks like it carries
// personal data: a key such as email or name, or a value that is an email
// address. A webhook leaves the platform for a customer's system; it
// carries ids, and the receiver looks a person up through the API if it
// needs to.
func CheckData(data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("webhook: data is not JSON: %w", err)
	}
	if len(raw) > MaxData {
		return fmt.Errorf("webhook: data is over %d bytes", MaxData)
	}
	return checkValue("data", data)
}

func checkValue(path string, v any) error {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if personal[strings.ToLower(k)] {
				return fmt.Errorf("webhook: %s.%s names a person; send an id", path, k)
			}
			if err := checkValue(path+"."+k, child); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range x {
			if err := checkValue(fmt.Sprintf("%s[%d]", path, i), child); err != nil {
				return err
			}
		}
	case string:
		if emailShape.MatchString(x) {
			return fmt.Errorf("webhook: %s holds an email address; send an id", path)
		}
	}
	return nil
}
