// Package plan is the one place that says what each plan band allows. Every
// service that gates an action asks here rather than keeping a rule of its
// own, and asks at the moment of the action: a plan change takes effect on
// the next attempt, with no sign-out and nothing cached.
//
// The bands, their limits and their features are a registry the product
// fills at start (see Registry): the template ships a default of free, team,
// business and enterprise with one limit, users, so it runs out of the box.
// A product replaces the bands, adds limits ("projects", "storage_gb") with
// a value per band, gates its own features, and registers the consequences
// its downgrade checklist shows: in code (Default.SetBands and the Register
// methods), or, when it runs the template's services unchanged, through
// PLANS (ParseConfig), which every service that reads plans loads at start.
// Every check reads the registry at the moment of the call.
//
// Plans are banded and priced flat per band. A downgrade closes doors going
// forward; it never deletes anything or removes anyone.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Band is a plan band's name: lower case, as the organization record and
// the billing provider's price map name it.
type Band string

// Feature is something a band either allows or refuses outright.
type Feature string

// Limit is a counted thing a band caps.
type Limit string

// Unlimited is the cap of a band that has none in the product.
const Unlimited = 0

// Users is the one limit the template itself enforces: active memberships.
// Deactivated people and guests do not count.
const Users Limit = "users"

// The features the template itself gates. Everything not registered is on
// every plan.
const (
	SCIM                    Feature = "scim"
	AuditExport             Feature = "audit_export"
	CustomerHostedDataPlane Feature = "customer_hosted_data_plane"
)

// BandSpec is one band: its name, what it caps and what it allows.
type BandSpec struct {
	Name Band `json:"name"`
	// Label is what a page calls it: "Team". A band with none is called by
	// its name, humanized ("team-50" is "Team 50").
	Label string `json:"label,omitempty"`
	// Limits is the cap for each registered limit; a limit absent here is
	// Unlimited on this band.
	Limits map[Limit]int `json:"limits,omitempty"`
	// Features allowed, beyond the ones every plan has.
	Features []Feature `json:"features,omitempty"`
	// Contractual marks a band sold by contract rather than self-serve: it is
	// invoiced, billing never moves an org into or out of it, and a platform
	// operator may set what is otherwise fixed (audit retention, say).
	Contractual bool `json:"contractual,omitempty"`
}

// Allows reports whether f is on this band.
func (b BandSpec) Allows(f Feature) bool {
	for _, x := range b.Features {
		if x == f {
			return true
		}
	}
	return false
}

// Cap is the band's cap on l; Unlimited when it has none.
func (b BandSpec) Cap(l Limit) int {
	if c, ok := b.Limits[l]; ok {
		return c
	}
	return Unlimited
}

// LimitSpec describes a registered limit.
type LimitSpec struct {
	Key Limit `json:"key"`
	// Label is the plural noun a message uses: "users", "projects". A limit
	// with none is called by its key, humanized.
	Label string `json:"label,omitempty"`
}

// FeatureSpec describes a registered feature.
type FeatureSpec struct {
	Key Feature `json:"key"`
	// Label is what a refusal calls it: "SCIM provisioning". A feature with
	// none is called by its key, humanized ("audit_export" is "audit export").
	Label string `json:"label,omitempty"`
	// LostCode and LostMessage are the downgrade checklist's line when a band
	// change takes the feature away; none when empty.
	LostCode    string `json:"lost_code,omitempty"`
	LostMessage string `json:"lost_message,omitempty"`
}

// Consequence is one line of the checklist an admin confirms before a
// downgrade: what stops working, and the rule that nothing is removed.
type Consequence struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ConsequenceFunc adds a product's lines to the downgrade checklist for a
// move from one band to another. Called for every preview and every
// downgrade notice; it must say nothing on an upgrade.
type ConsequenceFunc func(from, to BandSpec) []Consequence

// Registry is the bands, limits, features and downgrade consequences a
// product registers. Safe for concurrent use; registration is expected at
// start, before requests.
type Registry struct {
	mu           sync.RWMutex
	bands        []BandSpec
	limits       []LimitSpec
	features     []FeatureSpec
	consequences []ConsequenceFunc
}

// New is a registry with the template's own limit and features registered
// and no bands: SetBands fills it.
func New() *Registry {
	r := &Registry{}
	r.RegisterLimit(LimitSpec{Key: Users, Label: "users"})
	r.RegisterFeature(FeatureSpec{Key: SCIM, Label: "SCIM provisioning", LostCode: "scim_stops", LostMessage: "SCIM provisioning stops; people already provisioned stay."})
	r.RegisterFeature(FeatureSpec{Key: AuditExport, Label: "audit export", LostCode: "audit_export_stops", LostMessage: "Audit export is no longer available; the log itself is kept."})
	r.RegisterFeature(FeatureSpec{Key: CustomerHostedDataPlane, Label: "a customer-hosted data plane", LostCode: "data_plane_contractual", LostMessage: "The customer-hosted data plane is contractual; talk to us before changing this."})
	return r
}

// DefaultBands is the template's own ladder: free, team, business, and
// enterprise by contract.
func DefaultBands() []BandSpec {
	return []BandSpec{
		{Name: "free", Limits: map[Limit]int{Users: 10}},
		{Name: "team", Limits: map[Limit]int{Users: 50}},
		{Name: "business", Limits: map[Limit]int{Users: 200}},
		{Name: "enterprise", Contractual: true, Features: []Feature{SCIM, AuditExport, CustomerHostedDataPlane}},
	}
}

// Default is the registry the package functions read. A product fills it at
// start; the template's own ladder is in it until then.
var Default = func() *Registry {
	r := New()
	r.SetBands(DefaultBands())
	return r
}()

// SetBands replaces the ladder, lowest first. Names must be unique and
// every limit or feature a band names must be registered; a bad ladder
// panics, because it is a programming error at start, not a request.
//
// There must be at least one band, and no cap may be below zero. A band with
// no label is called by its name, humanized. The registry keeps its own copy.
func (r *Registry) SetBands(bands []BandSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkBands(bands, nil, nil); err != nil {
		panic(err.Error())
	}
	r.bands = make([]BandSpec, len(bands))
	for i, b := range bands {
		if b.Label == "" {
			b.Label = Humanize(string(b.Name))
		}
		r.bands[i] = b.clone()
	}
}

// checkBands is why bands cannot be the ladder, if they cannot. A limit or
// feature a band names must be registered, or be in limits or features: a
// configuration that registers them in the same breath. r.mu is held.
func (r *Registry) checkBands(bands []BandSpec, limits map[Limit]bool, features map[Feature]bool) error {
	if len(bands) == 0 {
		return errors.New("plan: a ladder needs at least one band")
	}
	seen := map[Band]bool{}
	for _, b := range bands {
		if b.Name == "" || seen[b.Name] {
			return fmt.Errorf("plan: band %q is empty or repeated", b.Name)
		}
		seen[b.Name] = true
		for l, c := range b.Limits {
			if r.limit(l) == nil && !limits[l] {
				return fmt.Errorf("plan: band %q caps unregistered limit %q", b.Name, l)
			}
			if c < 0 {
				return fmt.Errorf("plan: band %q caps %q below zero", b.Name, l)
			}
		}
		for _, f := range b.Features {
			if r.feature(f) == nil && !features[f] {
				return fmt.Errorf("plan: band %q allows unregistered feature %q", b.Name, f)
			}
		}
	}
	return nil
}

// clone is b with its own limits and features, so a change to the caller's
// map or slice never reaches the registry, or the other way.
func (b BandSpec) clone() BandSpec {
	limits := make(map[Limit]int, len(b.Limits))
	for l, c := range b.Limits {
		limits[l] = c
	}
	b.Limits = limits
	b.Features = append([]Feature(nil), b.Features...)
	return b
}

// Humanize is a key or a band's name as a label: separators become spaces
// and the first letter is upper case ("team-50" is "Team 50").
func Humanize(s string) string {
	s = strings.NewReplacer("-", " ", "_", " ").Replace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// RegisterLimit adds a limit a product caps per band, replacing one with
// the same key. A limit with no label is called by its key, humanized; one
// with no key panics.
func (r *Registry) RegisterLimit(l LimitSpec) {
	if l.Key == "" {
		panic("plan: a limit needs a key")
	}
	if l.Label == "" {
		l.Label = strings.ToLower(Humanize(string(l.Key)))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.limits {
		if x.Key == l.Key {
			r.limits[i] = l
			return
		}
	}
	r.limits = append(r.limits, l)
}

// RegisterFeature adds a feature a product gates, replacing one with the
// same key. A feature with no label is called by its key, humanized; one
// with no key panics.
func (r *Registry) RegisterFeature(f FeatureSpec) {
	if f.Key == "" {
		panic("plan: a feature needs a key")
	}
	if f.Label == "" {
		f.Label = strings.ToLower(Humanize(string(f.Key)))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.features {
		if x.Key == f.Key {
			r.features[i] = f
			return
		}
	}
	r.features = append(r.features, f)
}

// RegisterConsequence adds a product's lines to the downgrade checklist.
func (r *Registry) RegisterConsequence(fn ConsequenceFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consequences = append(r.consequences, fn)
}

func (r *Registry) limit(l Limit) *LimitSpec {
	for i := range r.limits {
		if r.limits[i].Key == l {
			return &r.limits[i]
		}
	}
	return nil
}

func (r *Registry) feature(f Feature) *FeatureSpec {
	for i := range r.features {
		if r.features[i].Key == f {
			return &r.features[i]
		}
	}
	return nil
}

// Bands is every band, lowest first.
func (r *Registry) Bands() []Band {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Band, len(r.bands))
	for i, b := range r.bands {
		out[i] = b.Name
	}
	return out
}

// Ladder is every band's spec, lowest first, labelled: the catalogue a page
// shows. The copies are the caller's.
func (r *Registry) Ladder() []BandSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]BandSpec, len(r.bands))
	for i, b := range r.bands {
		out[i] = b.clone()
	}
	return out
}

// Limits is every registered limit, in registration order.
func (r *Registry) Limits() []LimitSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]LimitSpec(nil), r.limits...)
}

// Features is every registered feature, in registration order.
func (r *Registry) Features() []FeatureSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]FeatureSpec(nil), r.features...)
}

// Parse is the band named by s.
func (r *Registry) Parse(s string) (Band, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.bands {
		if string(b.Name) == s {
			return b.Name, nil
		}
	}
	return "", fmt.Errorf("plan: %q is not a plan", s)
}

// For is what band b allows. An unknown band gets the lowest band's limits:
// the safe answer when a record is somehow wrong.
func (r *Registry) For(b Band) BandSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, x := range r.bands {
		if x.Name == b {
			return x
		}
	}
	if len(r.bands) == 0 {
		return BandSpec{}
	}
	return r.bands[0]
}

// Lowest is the first band: where a new org starts, and where a lapsed
// subscription lands.
func (r *Registry) Lowest() Band {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.bands) == 0 {
		return ""
	}
	return r.bands[0].Name
}

// Next is the band above b, or "" at the top.
func (r *Registry) Next(b Band) Band {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i, x := range r.bands {
		if x.Name == b && i+1 < len(r.bands) {
			return r.bands[i+1].Name
		}
	}
	return ""
}

// Rank orders bands: a lower rank is a lower band. Unknown bands rank lowest.
func (r *Registry) Rank(b Band) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i, x := range r.bands {
		if x.Name == b {
			return i
		}
	}
	return -1
}

// Contractual reports whether b is sold by contract rather than self-serve.
func (r *Registry) Contractual(b Band) bool { return r.For(b).Contractual && r.Rank(b) >= 0 }

// SelfServe is the paid bands billing sells, lowest first: everything above
// the lowest band that is not contractual.
func (r *Registry) SelfServe() []Band {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Band
	for i, x := range r.bands {
		if i > 0 && !x.Contractual {
			out = append(out, x.Name)
		}
	}
	return out
}

// Refusal is a plan saying no. It names the plan and, where there is one,
// the band that would allow it, so the message the person sees and the
// client's upgrade prompt both come from here.
type Refusal struct {
	Plan Band
	// Limit is what was hit: the limit's key, or the feature.
	Limit string
	// Required is the lowest band that would allow it, when one exists.
	Required Band
	Message  string
}

func (r *Refusal) Error() string { return "plan: " + r.Message }

// Code is the error envelope's stable code for a refusal.
const Code = "plan.limit_reached"

// Fields is the error envelope's fields for a refusal.
func (r *Refusal) Fields() map[string]string {
	f := map[string]string{"plan": string(r.Plan), "limit": r.Limit}
	if r.Required != "" {
		f["required_plan"] = string(r.Required)
	}
	return f
}

// AsRefusal is the Refusal in err, if it is one.
func AsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// CheckLimit is nil when an org on band b that has current of limit l may
// add one more. The wall is soft: nothing already there is affected, and
// the next one over the cap is what is refused. An unregistered limit is
// never refused.
func (r *Registry) CheckLimit(b Band, l Limit, current int) error {
	r.mu.RLock()
	spec := r.limit(l)
	r.mu.RUnlock()
	if spec == nil {
		return nil
	}
	cap := r.For(b).Cap(l)
	if cap == Unlimited || current < cap {
		return nil
	}
	var required Band
	for _, x := range r.above(b) {
		if c := x.Cap(l); c == Unlimited || c > current {
			required = x.Name
			break
		}
	}
	msg := fmt.Sprintf("The %s plan allows %d %s.", b, cap, spec.Label)
	if required != "" {
		msg = fmt.Sprintf("The %s plan allows %d %s; the next plan up is %s.", b, cap, spec.Label, required)
	}
	return &Refusal{Plan: b, Limit: string(l), Required: required, Message: msg}
}

// above is the bands above b, lowest first: where a refusal looks for the
// band that would allow it. A band the registry does not know is below
// every band.
func (r *Registry) above(b Band) []BandSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i, x := range r.bands {
		if x.Name == b {
			return append([]BandSpec(nil), r.bands[i+1:]...)
		}
	}
	return append([]BandSpec(nil), r.bands...)
}

// CheckUsers is CheckLimit for active members.
func (r *Registry) CheckUsers(b Band, active int) error { return r.CheckLimit(b, Users, active) }

// CheckFeature is nil when f is on band b.
func (r *Registry) CheckFeature(b Band, f Feature) error {
	if r.For(b).Allows(f) {
		return nil
	}
	var required Band
	for _, x := range r.above(b) {
		if x.Allows(f) {
			required = x.Name
			break
		}
	}
	r.mu.RLock()
	label := string(f)
	if spec := r.feature(f); spec != nil && spec.Label != "" {
		label = spec.Label
	}
	r.mu.RUnlock()
	msg := fmt.Sprintf("The %s plan does not include %s.", b, label)
	if required != "" {
		msg = fmt.Sprintf("The %s plan does not include %s; it is on %s and above.", b, label, required)
	}
	return &Refusal{Plan: b, Limit: string(f), Required: required, Message: msg}
}

// Downgrade is the checklist for moving from one band to another: a line
// for every limit that tightens, every registered feature that is lost, and
// whatever the product registered. Empty when nothing closes. The rule
// behind every line: nothing is deleted and nobody is removed.
func (r *Registry) Downgrade(from, to Band) []Consequence {
	f, t := r.For(from), r.For(to)
	r.mu.RLock()
	limits := append([]LimitSpec(nil), r.limits...)
	features := append([]FeatureSpec(nil), r.features...)
	fns := append([]ConsequenceFunc(nil), r.consequences...)
	r.mu.RUnlock()
	var out []Consequence
	for _, l := range limits {
		if tc, fc := t.Cap(l.Key), f.Cap(l.Key); tc != Unlimited && (fc == Unlimited || fc > tc) {
			label := strings.ToUpper(l.Label[:1]) + l.Label[1:]
			out = append(out, Consequence{Code: string(l.Key) + "_over_cap_kept",
				Message: fmt.Sprintf("%s beyond the new cap of %d stay; no new ones until under it.", label, tc)})
		}
	}
	for _, x := range features {
		if x.LostCode != "" && f.Allows(x.Key) && !t.Allows(x.Key) {
			out = append(out, Consequence{Code: x.LostCode, Message: x.LostMessage})
		}
	}
	for _, fn := range fns {
		out = append(out, fn(f, t)...)
	}
	return out
}

// Description is one band as the plan endpoint shows it: every registered
// limit's cap (Unlimited for none) and the features on it.
type Description struct {
	Band        Band
	Label       string
	Contractual bool
	Limits      map[string]int
	Features    []string
}

// Describe is band b, described.
func (r *Registry) Describe(b Band) Description {
	spec := r.For(b)
	out := Description{Band: spec.Name, Label: spec.Label, Contractual: spec.Contractual, Limits: map[string]int{}, Features: []string{}}
	for _, l := range r.Limits() {
		out.Limits[string(l.Key)] = spec.Cap(l.Key)
	}
	for _, f := range spec.Features {
		out.Features = append(out.Features, string(f))
	}
	sort.Strings(out.Features)
	return out
}

// The package functions read Default.

// Ladder is every band's spec in Default, lowest first.
func Ladder() []BandSpec { return Default.Ladder() }

// Bands is every band in Default, lowest first.
func Bands() []Band { return Default.Bands() }

// Parse is the band in Default named by s.
func Parse(s string) (Band, error) { return Default.Parse(s) }

// For is what band b allows in Default.
func For(b Band) BandSpec { return Default.For(b) }

// Lowest is Default's first band.
func Lowest() Band { return Default.Lowest() }

// Next is the band above b in Default, or "" at the top.
func Next(b Band) Band { return Default.Next(b) }

// Rank orders Default's bands.
func Rank(b Band) int { return Default.Rank(b) }

// Contractual reports whether b is sold by contract in Default.
func Contractual(b Band) bool { return Default.Contractual(b) }

// SelfServe is the paid bands billing sells, from Default.
func SelfServe() []Band { return Default.SelfServe() }

// CheckLimit is Default's.
func CheckLimit(b Band, l Limit, current int) error { return Default.CheckLimit(b, l, current) }

// CheckUsers is Default's.
func CheckUsers(b Band, active int) error { return Default.CheckUsers(b, active) }

// CheckFeature is Default's.
func CheckFeature(b Band, f Feature) error { return Default.CheckFeature(b, f) }

// Downgrade is Default's checklist.
func Downgrade(from, to Band) []Consequence { return Default.Downgrade(from, to) }

// Describe is Default's.
func Describe(b Band) Description { return Default.Describe(b) }

// Config is what a product declares in PLANS when it runs the template's
// services unchanged: its limits and features, registered beside the
// template's own, and its ladder, which replaces the template's when given.
//
//	{"limits":[{"key":"projects","label":"projects"}],
//	 "features":[{"key":"exports","label":"scheduled exports","lost_code":"exports_stop","lost_message":"Scheduled exports stop."}],
//	 "bands":[{"name":"free","label":"Free","limits":{"users":10,"projects":3}},
//	          {"name":"team","limits":{"users":50,"projects":25},"features":["exports"]},
//	          {"name":"enterprise","contractual":true,"features":["exports","scim","audit_export"]}]}
//
// Downgrade consequences beyond a tightened limit or a lost feature are code
// (RegisterConsequence); they have no configuration.
type Config struct {
	Limits   []LimitSpec   `json:"limits,omitempty"`
	Features []FeatureSpec `json:"features,omitempty"`
	Bands    []BandSpec    `json:"bands,omitempty"`
}

// ParseConfig reads PLANS' value; empty is nothing. A field it does not
// know, or a limit or feature with no key or a repeated one, is refused.
// The ladder is checked by Load, against what the registry holds.
func ParseConfig(s string) (Config, error) {
	var c Config
	if strings.TrimSpace(s) == "" {
		return c, nil
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("plan: plans: %w", err)
	}
	limits := map[Limit]bool{}
	for _, l := range c.Limits {
		if l.Key == "" || limits[l.Key] {
			return Config{}, fmt.Errorf("plan: limit %q is empty or repeated", l.Key)
		}
		limits[l.Key] = true
	}
	features := map[Feature]bool{}
	for _, f := range c.Features {
		if f.Key == "" || features[f.Key] {
			return Config{}, fmt.Errorf("plan: feature %q is empty or repeated", f.Key)
		}
		features[f.Key] = true
	}
	if c.Bands != nil && len(c.Bands) == 0 {
		return Config{}, errors.New("plan: a ladder needs at least one band")
	}
	return c, nil
}

// Load registers PLANS' value in r: its limits and features, then its
// ladder when it has one. The ladder is checked as SetBands checks it,
// before anything changes, so a bad value is an error at start and leaves
// r as it was.
func (r *Registry) Load(s string) error {
	c, err := ParseConfig(s)
	if err != nil {
		return err
	}
	if len(c.Bands) > 0 {
		limits, features := map[Limit]bool{}, map[Feature]bool{}
		for _, l := range c.Limits {
			limits[l.Key] = true
		}
		for _, f := range c.Features {
			features[f.Key] = true
		}
		r.mu.RLock()
		err := r.checkBands(c.Bands, limits, features)
		r.mu.RUnlock()
		if err != nil {
			return err
		}
	}
	for _, l := range c.Limits {
		r.RegisterLimit(l)
	}
	for _, f := range c.Features {
		r.RegisterFeature(f)
	}
	if len(c.Bands) > 0 {
		r.SetBands(c.Bands)
	}
	return nil
}
