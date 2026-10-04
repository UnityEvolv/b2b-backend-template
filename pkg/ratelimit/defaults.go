package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// The rules the template's own endpoints use. A service binds its endpoints
// to these rather than inventing its own number; changing a number is a
// change to this file, reviewed in one place. A product registers its own
// (see Registry).
var (
	// Every request to a service, per client address, counted in front of
	// authentication so token guessing is slowed too. Generous, because a whole
	// office can share one address.
	PerAddress = Rule{Name: "address", Limit: 1200, Window: time.Minute}

	// Endpoints reachable without a token (sign-up, invite lookup), per client
	// address, on top of PerAddress.
	Unauthenticated = Rule{Name: "unauthenticated", Limit: 60, Window: time.Minute}

	// Ordinary authenticated reads and writes, per membership.
	AuthenticatedRead  = Rule{Name: "read", Limit: 600, Window: time.Minute}
	AuthenticatedWrite = Rule{Name: "write", Limit: 120, Window: time.Minute}

	// Failed sign-ins, per account and per address, counted with
	// Check/Penalize so only failures spend. Fails closed.
	FailedSignIn = Rule{Name: "signin-failed", Limit: 10, Window: 15 * time.Minute, FailClosed: true}
	// Password reset requests, per account. Fails closed.
	PasswordReset = Rule{Name: "password-reset", Limit: 3, Window: time.Hour, FailClosed: true}

	// Invites sent, per membership.
	InviteSend = Rule{Name: "invite-send", Limit: 50, Window: time.Hour}

	// An identity provider pushing users and groups over SCIM, per org. A
	// full sync is thousands of requests and providers retry hard, so this is
	// generous; it is there to stop one org starving the service.
	SCIM = Rule{Name: "scim", Limit: 2400, Window: time.Minute}

	// Every request made with an API key or a personal access token, per
	// key, across every service: counted where the key is resolved, by the
	// identity service, so a script is held to one allowance wherever it
	// calls. Fails open, as the ordinary limits do.
	APIKey = Rule{Name: "api-key", Limit: 600, Window: time.Minute}

	// Incoming webhooks from the billing and email providers, per address.
	Webhook = Rule{Name: "webhook", Limit: 3000, Window: time.Minute}
)

// Per is what a registered rule counts by.
type Per string

// What a rule can count by.
const (
	PerIP         Per = "ip"
	PerUser       Per = "user"
	PerMembership Per = "membership"
	PerOrg        Per = "org"
	// PerCaller is a rule the code keys itself: a sign-in counted by account
	// with Check and Penalize, a request counted by the API key it brought.
	// Only the template's own rules use it.
	PerCaller Per = ""
)

// Key is the KeyFunc for p; nil for PerCaller.
func (p Per) Key() KeyFunc {
	switch p {
	case PerIP:
		return ByIP
	case PerUser:
		return ByUser
	case PerMembership:
		return ByMembership
	case PerOrg:
		return ByOrg
	}
	return nil
}

// Registered is a rule and what it counts by, as registered.
type Registered struct {
	Rule
	Per Per
}

// Registry is the rules every limit is one of: the template's and the ones
// a product registers. Registering keeps names unique, so two rules never
// share a Redis bucket, and refuses a rule that is not a limit. Safe for
// concurrent use; registration is expected at start, before requests.
type Registry struct {
	mu    sync.RWMutex
	rules []Registered
}

// NewRegistry is a registry with the template's own rules.
func NewRegistry() *Registry {
	r := &Registry{}
	for _, x := range []Registered{
		{PerAddress, PerIP}, {Unauthenticated, PerIP},
		{AuthenticatedRead, PerMembership}, {AuthenticatedWrite, PerMembership},
		{FailedSignIn, PerCaller}, {PasswordReset, PerCaller},
		{InviteSend, PerMembership}, {SCIM, PerOrg}, {Webhook, PerIP},
		{APIKey, PerCaller},
	} {
		r.add(x)
	}
	return r
}

// Default is the registry a product registers its rules in. The template's
// own are in it until then.
var Default = NewRegistry()

// Register adds a product's rule, counted per, and returns it bound, for one
// line in a service's Limits table:
//
//	var ProjectCreate = ratelimit.Default.Register(ratelimit.Rule{Name: "project-create", Limit: 30, Window: time.Minute}, ratelimit.PerMembership)
//	...
//	"POST /v1/organizations/{org_id}/projects": ProjectCreate,
//
// A rule with no name, a limit or window that is not positive, a name
// already registered, or no key to count by panics: it is a programming
// error at start, not a request.
func (r *Registry) Register(rule Rule, per Per) Bound {
	key := per.Key()
	if key == nil {
		panic(fmt.Sprintf("ratelimit: rule %q counts by %q, not ip, user, membership or org", rule.Name, per))
	}
	r.add(Registered{rule, per})
	return On(rule, key)
}

func (r *Registry) add(x Registered) {
	if x.Name == "" || x.Limit <= 0 || x.Window <= 0 {
		panic(fmt.Sprintf("ratelimit: rule %q is not a limit", x.Name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, y := range r.rules {
		if y.Name == x.Name {
			panic(fmt.Sprintf("ratelimit: rule %q is already registered", x.Name))
		}
	}
	r.rules = append(r.rules, x)
}

// Rules is every registered rule, in registration order.
func (r *Registry) Rules() []Registered {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Registered(nil), r.rules...)
}

// Lookup is the registered rule called name.
func (r *Registry) Lookup(name string) (Registered, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, x := range r.rules {
		if x.Name == name {
			return x, true
		}
	}
	return Registered{}, false
}
