package plan

import (
	"fmt"
	"sort"
	"time"
)

// Override is one org's exception to its band, for one registered limit or
// feature: an enterprise deal with a higher seat cap, one extra feature, or
// a trial of a feature. A platform operator sets it, with an optional end;
// past the end it simply stops applying, at the next check, with nothing to
// run. Exactly one of Limit and Feature is set.
type Override struct {
	Limit   Limit
	Feature Feature
	// Cap replaces the band's cap on Limit; Unlimited lifts it.
	Cap int
	// Allowed grants Feature (true) or takes it away (false), whatever the
	// band says.
	Allowed bool
	// EndsAt is when the override stops applying; nil is never.
	EndsAt *time.Time
}

// InForce reports whether o applies at now: it has no end, or its end is
// still ahead.
func (o Override) InForce(now time.Time) bool { return o.EndsAt == nil || now.Before(*o.EndsAt) }

// Key is the limit's or the feature's key.
func (o Override) Key() string {
	if o.Limit != "" {
		return string(o.Limit)
	}
	return string(o.Feature)
}

// Entitlements is what one org may do: its band, then its overrides. Every
// gate reads it at the moment of the action, from a Source; the overrides
// past their end are ignored there and then, so nothing has to expire them.
type Entitlements struct {
	Band      Band
	Overrides []Override
}

// Of is band b with no overrides.
func Of(b Band) Entitlements { return Entitlements{Band: b} }


// LimitOverride is the override of l in force now, if there is one.
func (e Entitlements) LimitOverride(l Limit) (Override, bool) {
	t := time.Now()
	for _, o := range e.Overrides {
		if o.Limit == l && o.InForce(t) {
			return o, true
		}
	}
	return Override{}, false
}

// FeatureOverride is the override of f in force now, if there is one.
func (e Entitlements) FeatureOverride(f Feature) (Override, bool) {
	t := time.Now()
	for _, o := range e.Overrides {
		if o.Feature == f && o.InForce(t) {
			return o, true
		}
	}
	return Override{}, false
}

// InForce is the overrides that apply now, limits then features, each by key.
func (e Entitlements) InForce() []Override {
	t := time.Now()
	var out []Override
	for _, o := range e.Overrides {
		if o.InForce(t) {
			out = append(out, o)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Limit != "") != (out[j].Limit != "") {
			return out[i].Limit != ""
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// CapOf is the cap on l for an org with e: the override in force, else the
// band's.
func (r *Registry) CapOf(e Entitlements, l Limit) int {
	if o, ok := e.LimitOverride(l); ok {
		return o.Cap
	}
	return r.For(e.Band).Cap(l)
}

// AllowsOf reports whether f is on for an org with e: the override in
// force, else the band.
func (r *Registry) AllowsOf(e Entitlements, f Feature) bool {
	if o, ok := e.FeatureOverride(f); ok {
		return o.Allowed
	}
	return r.For(e.Band).Allows(f)
}

// CheckLimitOf is CheckLimit for an org with e: the band's cap, then its
// override. A refusal under an override says it is the organization's
// agreement, and names the band that would allow it when one would.
func (r *Registry) CheckLimitOf(e Entitlements, l Limit, current int) error {
	o, ok := e.LimitOverride(l)
	if !ok {
		return r.CheckLimit(e.Band, l, current)
	}
	r.mu.RLock()
	spec := r.limit(l)
	r.mu.RUnlock()
	if spec == nil || o.Cap == Unlimited || current < o.Cap {
		return nil
	}
	var required Band
	for _, x := range r.above(e.Band) {
		if c := x.Cap(l); c == Unlimited || c > current {
			required = x.Name
			break
		}
	}
	msg := fmt.Sprintf("The organization's agreement allows %d %s.", o.Cap, spec.Label)
	if required != "" {
		msg = fmt.Sprintf("The organization's agreement allows %d %s; the %s plan allows more.", o.Cap, spec.Label, required)
	}
	return &Refusal{Plan: e.Band, Limit: string(l), Required: required, Message: msg}
}

// CheckFeatureOf is CheckFeature for an org with e: a feature granted by an
// override is on whatever the band says, and one taken away is off.
func (r *Registry) CheckFeatureOf(e Entitlements, f Feature) error {
	o, ok := e.FeatureOverride(f)
	if !ok {
		return r.CheckFeature(e.Band, f)
	}
	if o.Allowed {
		return nil
	}
	r.mu.RLock()
	label := string(f)
	if spec := r.feature(f); spec != nil && spec.Label != "" {
		label = spec.Label
	}
	r.mu.RUnlock()
	return &Refusal{Plan: e.Band, Limit: string(f), Message: fmt.Sprintf("The organization's agreement does not include %s.", label)}
}

// DescribeOf is e's band described with what the org may actually do:
// every registered limit at its effective cap and every feature on for it,
// with the overrides in force that made the difference.
func (r *Registry) DescribeOf(e Entitlements) Description {
	d := r.Describe(e.Band)
	for _, l := range r.Limits() {
		d.Limits[string(l.Key)] = r.CapOf(e, l.Key)
	}
	d.Features = []string{}
	for _, f := range r.Features() {
		if r.AllowsOf(e, f.Key) {
			d.Features = append(d.Features, string(f.Key))
		}
	}
	sort.Strings(d.Features)
	for _, o := range e.InForce() {
		if r.CheckOverride(o) == nil {
			d.Overrides = append(d.Overrides, o)
		}
	}
	return d
}

// CheckOverride is nil when o names one registered limit or feature, with a
// cap that is not below zero. A platform operator's input is checked with it.
func (r *Registry) CheckOverride(o Override) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch {
	case (o.Limit == "") == (o.Feature == ""):
		return fmt.Errorf("plan: an override is of one limit or one feature")
	case o.Limit != "" && r.limit(o.Limit) == nil:
		return fmt.Errorf("plan: %q is not a registered limit", o.Limit)
	case o.Feature != "" && r.feature(o.Feature) == nil:
		return fmt.Errorf("plan: %q is not a registered feature", o.Feature)
	case o.Cap < 0:
		return fmt.Errorf("plan: a cap is not below zero")
	}
	return nil
}

// Cap is the cap on l for an org with e, from Default.
func (e Entitlements) Cap(l Limit) int { return Default.CapOf(e, l) }

// Allows reports whether f is on for an org with e, from Default.
func (e Entitlements) Allows(f Feature) bool { return Default.AllowsOf(e, f) }

// CheckLimit is Default's CheckLimitOf for e.
func (e Entitlements) CheckLimit(l Limit, current int) error {
	return Default.CheckLimitOf(e, l, current)
}

// CheckUsers is CheckLimit for active members.
func (e Entitlements) CheckUsers(active int) error { return e.CheckLimit(Users, active) }

// CheckFeature is Default's CheckFeatureOf for e.
func (e Entitlements) CheckFeature(f Feature) error { return Default.CheckFeatureOf(e, f) }

// Describe is Default's DescribeOf for e.
func (e Entitlements) Describe() Description { return Default.DescribeOf(e) }
