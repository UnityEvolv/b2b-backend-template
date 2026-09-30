// Package dataowner is the registry of services that hold an org's or a
// person's data: the one list offboarding, exports, account
// deletion, key access and service tokens read, so a product's own service
// joins all of them by being registered, and nothing in the template names
// it.
//
// Each owner declares where it is and what it answers, in pkg/orgdata's
// contract:
//
//   - Export: an org's export part and a person's, GET …/data.
//   - Purge: deleting a closing org, DELETE /v1/internal/organizations/{org}/data.
//   - Erase: forgetting one member, DELETE …/memberships/{membership}/data.
//   - Decrypt: fetching an org's wrapped data key to decrypt its secrets,
//     which KMS IAM must also allow (docs/encryption.md).
//
// The template registers its own six. A product adds its services in code
// with Default.Register, or, running the template's services unchanged,
// through DATA_OWNERS (Parse), which every service reads at start: the
// organization service to export and purge them, the user service to erase
// members there, and every service to accept their service tokens.
package dataowner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Owner is one service that holds data, and what it answers.
type Owner struct {
	// Name is the service's name: the one its service tokens carry.
	Name string `json:"name"`
	// URL is its base URL. Empty, it is read from <NAME>_URL (URLVar),
	// which is how the template's own are configured.
	URL string `json:"url,omitempty"`
	// Export: it answers for an org's export and for a person's.
	Export bool `json:"export"`
	// Purge: it deletes a closing org and says how many rows remain.
	Purge bool `json:"purge"`
	// Erase: it forgets what it keeps under one membership when the
	// person's account is deleted.
	Erase bool `json:"erase"`
	// Decrypt: it may fetch an org's wrapped data key.
	Decrypt bool `json:"decrypt"`
	// PurgeLast is purged after every other owner: a service the others'
	// purges may still write to (audit).
	PurgeLast bool `json:"purge_last,omitempty"`
}

// URLVar is the setting its base URL is read from when URL is empty:
// NOTIFICATION_URL for notification, PROJECT_FILES_URL for project-files.
func (o Owner) URLVar() string {
	return strings.ToUpper(strings.ReplaceAll(o.Name, "-", "_")) + "_URL"
}

// Registry is the services that hold data: the template's and the ones a
// product registers. Safe for concurrent use; registration is expected at
// start, before requests.
type Registry struct {
	mu     sync.RWMutex
	owners []Owner
}

// name is what a service may be called: its token's subject is
// "service:<name>" and its URL setting follows from it.
var name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,50}$`)

// New is a registry with the template's own owners. Every one exports and
// purges; notification also forgets a member; identity decrypts; audit is
// purged last, because the other purges are audited.
func New() *Registry {
	r := &Registry{}
	for _, o := range []Owner{
		{Name: "notification", Export: true, Purge: true, Erase: true},
		{Name: "billing", Export: true, Purge: true},
		{Name: "authorization", Export: true, Purge: true},
		{Name: "identity", Export: true, Purge: true, Decrypt: true},
		{Name: "user", Export: true, Purge: true},
		{Name: "audit", Export: true, Purge: true, PurgeLast: true},
	} {
		r.Register(o)
	}
	return r
}

// Default is the registry every service reads. A product adds its owners
// at start, in code or from DATA_OWNERS; the template's own are in it
// until then.
var Default = New()

// Register adds an owner, replacing one with the same name. A name that is
// not a plain lower-case name panics: it is a programming error at start,
// not a request.
func (r *Registry) Register(o Owner) {
	if err := check(o); err != nil {
		panic(err.Error())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.owners {
		if x.Name == o.Name {
			r.owners[i] = o
			return
		}
	}
	r.owners = append(r.owners, o)
}

func check(o Owner) error {
	if !name.MatchString(o.Name) {
		return fmt.Errorf("dataowner: %q cannot be a service name", o.Name)
	}
	return nil
}

// Parse reads owners from configuration, for a product that runs the
// template's services unchanged: a JSON list such as
//
//	[{"name":"projects","url":"http://projects:8080","export":true,"purge":true,"erase":true}]
//
// An entry with no capability is a service that holds nothing here but
// calls the template's services with its own token. Each is checked as
// Register would; empty is none.
func Parse(s string) ([]Owner, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var in []Owner
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("dataowner: data owners: %w", err)
	}
	for _, o := range in {
		if err := check(o); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// Load registers every owner in s, DATA_OWNERS' value, in r.
func (r *Registry) Load(s string) error {
	owners, err := Parse(s)
	if err != nil {
		return err
	}
	for _, o := range owners {
		r.Register(o)
	}
	return nil
}

// Owners is every registered owner, in registration order.
func (r *Registry) Owners() []Owner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.owners)
}

func (r *Registry) where(keep func(Owner) bool) []Owner {
	var out []Owner
	for _, o := range r.Owners() {
		if keep(o) {
			out = append(out, o)
		}
	}
	return out
}

// Exporters is every owner with an export part, in registration order.
func (r *Registry) Exporters() []Owner { return r.where(func(o Owner) bool { return o.Export }) }

// Purgers is every owner a purge empties, in the order it is emptied:
// registration order, with the PurgeLast ones after the rest.
func (r *Registry) Purgers() []Owner {
	first := r.where(func(o Owner) bool { return o.Purge && !o.PurgeLast })
	return append(first, r.where(func(o Owner) bool { return o.Purge && o.PurgeLast })...)
}

// Erasers is every owner that forgets a member.
func (r *Registry) Erasers() []Owner { return r.where(func(o Owner) bool { return o.Erase }) }

// Decrypting is the name of every owner that may fetch a wrapped key: the
// list KMS IAM grants decrypt to.
func (r *Registry) Decrypting() []string {
	var out []string
	for _, o := range r.where(func(o Owner) bool { return o.Decrypt }) {
		out = append(out, o.Name)
	}
	return out
}

// Known reports whether name is registered.
func (r *Registry) Known(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.ContainsFunc(r.owners, func(o Owner) bool { return o.Name == name })
}

// Locate fills in the URL of every owner need selects: its own, or the
// value of its URLVar from lookup. An owner with neither is an error naming
// the setting, so a misconfigured deploy fails at start instead of skipping
// a service when its turn comes. The organization service locates the
// owners that hold org data, the user service the ones that erase.
func (r *Registry) Locate(lookup func(string) string, need func(Owner) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var missing []string
	for i, o := range r.owners {
		if !need(o) {
			continue
		}
		if o.URL == "" {
			r.owners[i].URL = strings.TrimSpace(lookup(o.URLVar()))
		}
		if r.owners[i].URL == "" {
			missing = append(missing, o.URLVar())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("dataowner: %s not set", strings.Join(missing, ", "))
	}
	return nil
}

// HoldsOrgData reports whether o is in an org's export or its purge.
func (o Owner) HoldsOrgData() bool { return o.Export || o.Purge }

// Erases reports whether o forgets a member.
func (o Owner) Erases() bool { return o.Erase }

// Manifest is the registry as the deploy reads it (cmd/dataowners): every
// owner with what it answers, and the ones KMS lets decrypt.
type Manifest struct {
	Owners     []Owner  `json:"owners"`
	Decrypting []string `json:"decrypting"`
}

// Manifest is r's manifest, URLs left out: those are the deploy's own.
func (r *Registry) Manifest() Manifest {
	m := Manifest{Owners: []Owner{}, Decrypting: []string{}}
	for _, o := range r.Owners() {
		o.URL = ""
		m.Owners = append(m.Owners, o)
	}
	m.Decrypting = append(m.Decrypting, r.Decrypting()...)
	return m
}
