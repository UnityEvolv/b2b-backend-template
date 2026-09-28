// Package plan is the one place that says what each plan band allows
// (UO-138). Every story that gates a feature asks here rather than keeping a
// rule of its own, and asks at the moment of the action: a plan change takes
// effect on the next attempt, with no sign-out and nothing cached.
//
// Plans are banded by users and priced flat per band. A downgrade closes
// doors going forward; it never deletes anything or removes anyone.
package plan

import (
	"errors"
	"fmt"
	"time"
)

// Band is a plan band.
type Band string

// The bands, in order. Enterprise limits are contractual, not in the product.
const (
	Free       Band = "free"
	Team50     Band = "team-50"
	Team200    Band = "team-200"
	Team500    Band = "team-500"
	Enterprise Band = "enterprise"
)

// Bands is every band, lowest first.
var Bands = []Band{Free, Team50, Team200, Team500, Enterprise}

// Parse is the band named by s.
func Parse(s string) (Band, error) {
	for _, b := range Bands {
		if string(b) == s {
			return b, nil
		}
	}
	return "", fmt.Errorf("plan: %q is not a plan", s)
}

// Next is the band above b, or "" at the top.
func Next(b Band) Band {
	for i, x := range Bands {
		if x == b && i+1 < len(Bands) {
			return Bands[i+1]
		}
	}
	return ""
}

// Rank orders bands: a lower rank is a lower band. Unknown bands rank lowest.
func Rank(b Band) int {
	for i, x := range Bands {
		if x == b {
			return i
		}
	}
	return -1
}

// Unlimited is the cap of a band that has none in the product.
const Unlimited = 0

// BuiltInRoomCapacity is the built-in peer-to-peer provider's limit per room,
// on every plan, including paid. Room capacity follows the provider in use,
// never the plan: upgrading does not enlarge peer-to-peer rooms; adding a
// provider does.
const BuiltInRoomCapacity = 4

// Feature is something a band either allows or refuses outright.
type Feature string

// The gated features. Everything not listed is on every plan.
const (
	BringOwnRTC             Feature = "bring_own_rtc"
	BringOwnMessaging       Feature = "bring_own_messaging"
	OfficeAdminRole         Feature = "office_admin_role"
	RestrictedOffices       Feature = "restricted_offices"
	GuestInvites            Feature = "guest_invites"
	CallRecording           Feature = "call_recording"
	MessageRetentionSetting Feature = "message_retention_setting"
	SCIM                    Feature = "scim"
	AuditExport             Feature = "audit_export"
	CustomerHostedDataPlane Feature = "customer_hosted_data_plane"
)

// Limits is what a band decides.
type Limits struct {
	// Users is the cap on active memberships; deactivated people and guests
	// do not count. Unlimited on enterprise.
	Users int
	// Offices is the cap on active offices. Unlimited on enterprise.
	Offices int
	// MessageRetention on the built-in messaging provider: fixed on free,
	// configurable between the two on team and enterprise. On a bring-your-
	// own provider, retention is whatever the org's account gives them.
	MinMessageRetention time.Duration
	MaxMessageRetention time.Duration
	// AttachmentBytes is the largest file in chat.
	AttachmentBytes int64
	// Features allowed, beyond the ones every plan has.
	Features []Feature
}

// Allows reports whether f is on this plan.
func (l Limits) Allows(f Feature) bool {
	for _, x := range l.Features {
		if x == f {
			return true
		}
	}
	return false
}

var teamFeatures = []Feature{BringOwnRTC, BringOwnMessaging, OfficeAdminRole, RestrictedOffices, GuestInvites, CallRecording, MessageRetentionSetting}

var table = map[Band]Limits{
	Free:       {Users: 10, Offices: 5, MinMessageRetention: 12 * time.Hour, MaxMessageRetention: 12 * time.Hour, AttachmentBytes: 10 << 20},
	Team50:     {Users: 50, Offices: 20, MinMessageRetention: 12 * time.Hour, MaxMessageRetention: 30 * 24 * time.Hour, AttachmentBytes: 100 << 20, Features: teamFeatures},
	Team200:    {Users: 200, Offices: 20, MinMessageRetention: 12 * time.Hour, MaxMessageRetention: 30 * 24 * time.Hour, AttachmentBytes: 100 << 20, Features: teamFeatures},
	Team500:    {Users: 500, Offices: 20, MinMessageRetention: 12 * time.Hour, MaxMessageRetention: 30 * 24 * time.Hour, AttachmentBytes: 100 << 20, Features: teamFeatures},
	Enterprise: {Users: Unlimited, Offices: Unlimited, MinMessageRetention: 12 * time.Hour, MaxMessageRetention: 30 * 24 * time.Hour, AttachmentBytes: 100 << 20, Features: append(append([]Feature{}, teamFeatures...), SCIM, AuditExport, CustomerHostedDataPlane)},
}

// For is what band b allows. An unknown band gets free's limits: the safe
// answer when a record is somehow wrong.
func For(b Band) Limits {
	if l, ok := table[b]; ok {
		return l
	}
	return table[Free]
}

// Refusal is a plan saying no. It names the plan and, where there is one,
// the next band up, so the message the person sees and the client's
// upgrade prompt both come from here.
type Refusal struct {
	Plan Band
	// Limit is what was hit: "users", "offices", "attachment_bytes",
	// "message_retention", or the feature.
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

// CheckUsers is nil when an org on band b with active members may add one
// more. The wall is soft: nobody already in is affected, and the next invite
// over the cap is what is refused.
func CheckUsers(b Band, active int) error {
	cap := For(b).Users
	if cap == Unlimited || active < cap {
		return nil
	}
	return &Refusal{Plan: b, Limit: "users", Required: Next(b),
		Message: fmt.Sprintf("The %s plan allows %d users; the next plan up is %s.", b, cap, Next(b))}
}

// CheckOffices is nil when an org on band b with active offices may add one.
func CheckOffices(b Band, active int) error {
	cap := For(b).Offices
	if cap == Unlimited || active < cap {
		return nil
	}
	return &Refusal{Plan: b, Limit: "offices", Required: Next(b),
		Message: fmt.Sprintf("The %s plan allows %d offices; the next plan up is %s.", b, cap, Next(b))}
}

// CheckFeature is nil when f is on band b.
func CheckFeature(b Band, f Feature) error {
	if For(b).Allows(f) {
		return nil
	}
	required := Next(b)
	for _, x := range Bands {
		if For(x).Allows(f) {
			required = x
			break
		}
	}
	return &Refusal{Plan: b, Limit: string(f), Required: required,
		Message: fmt.Sprintf("The %s plan does not include %s; it is on %s and above.", b, describe(f), required)}
}

// CheckAttachment is nil when a chat attachment of size bytes fits band b.
func CheckAttachment(b Band, size int64) error {
	l := For(b)
	if size <= l.AttachmentBytes {
		return nil
	}
	return &Refusal{Plan: b, Limit: "attachment_bytes", Required: Next(b),
		Message: fmt.Sprintf("The %s plan allows attachments up to %d MB.", b, l.AttachmentBytes>>20)}
}

// CheckRetention is nil when band b lets the built-in messaging retention be
// set to d. On free it is fixed, so any change is refused.
func CheckRetention(b Band, d time.Duration) error {
	l := For(b)
	if !l.Allows(MessageRetentionSetting) {
		return &Refusal{Plan: b, Limit: "message_retention", Required: Next(b),
			Message: fmt.Sprintf("The %s plan keeps messages for %s; retention is configurable on %s and above.", b, humanDuration(l.MinMessageRetention), Next(b))}
	}
	if d < l.MinMessageRetention || d > l.MaxMessageRetention {
		return &Refusal{Plan: b, Limit: "message_retention",
			Message: fmt.Sprintf("The %s plan keeps messages for between %s and %s.", b, humanDuration(l.MinMessageRetention), humanDuration(l.MaxMessageRetention))}
	}
	return nil
}

func describe(f Feature) string {
	switch f {
	case BringOwnRTC:
		return "bringing your own call provider"
	case BringOwnMessaging:
		return "bringing your own messaging provider"
	case OfficeAdminRole:
		return "the Office Admin role"
	case RestrictedOffices:
		return "restricted offices"
	case GuestInvites:
		return "guest invites"
	case CallRecording:
		return "call recording"
	case MessageRetentionSetting:
		return "a message retention setting"
	case SCIM:
		return "SCIM provisioning"
	case AuditExport:
		return "audit export"
	case CustomerHostedDataPlane:
		return "a customer-hosted data plane"
	}
	return string(f)
}

func humanDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}

// Consequence is one line of the checklist an admin confirms before a
// downgrade: what stops working, and the rule that nothing is removed.
type Consequence struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Downgrade is the checklist for moving from one band to another. Empty when
// nothing closes. Counts of what is over a new cap come from the services
// that own offices, users and rooms; this is the rule for each.
func Downgrade(from, to Band) []Consequence {
	f, t := For(from), For(to)
	var out []Consequence
	add := func(code, message string) { out = append(out, Consequence{Code: code, Message: message}) }
	lost := func(x Feature) bool { return f.Allows(x) && !t.Allows(x) }
	if lost(OfficeAdminRole) {
		add("office_admins_kept", "Existing Office Admins keep their role; no new assignments.")
	}
	if lost(RestrictedOffices) {
		add("restricted_offices_kept", "Restricted offices stay restricted; the flag cannot be turned on for new offices. An org Admin still manages membership.")
	}
	if lost(GuestInvites) {
		add("guest_grants_run_out", "Existing guest grants run to expiry; no new invites and no extensions.")
	}
	if t.Offices != Unlimited && (f.Offices == Unlimited || f.Offices > t.Offices) {
		add("offices_over_limit_kept", fmt.Sprintf("Offices beyond the new limit of %d stay active; no new offices until under it.", t.Offices))
	}
	if t.Users != Unlimited && (f.Users == Unlimited || f.Users > t.Users) {
		add("users_over_cap_kept", fmt.Sprintf("Users beyond the new cap of %d stay active; no new invites until under it.", t.Users))
	}
	if lost(BringOwnRTC) {
		add("rooms_keep_capacity", fmt.Sprintf("Rooms with capacity above the built-in ceiling of %d keep it until next edited; the rooms that exceed it are listed.", BuiltInRoomCapacity))
		add("calls_finish_on_provider", "Calls on an external provider finish; the next call uses the built-in provider.")
	}
	if lost(CallRecording) {
		add("recording_finishes", "A recording in progress finishes; the next call has no record control.")
	}
	if lost(BringOwnMessaging) {
		add("messages_stay_on_provider", "Messages on a bring-your-own messaging provider stay on that account; new messages go to the built-in provider.")
	}
	if lost(MessageRetentionSetting) || t.MaxMessageRetention < f.MaxMessageRetention {
		add("retention_drops_forward", fmt.Sprintf("Built-in retention becomes %s for messages sent after the change; older messages expire on their original schedule.", humanDuration(t.MaxMessageRetention)))
	}
	if t.AttachmentBytes < f.AttachmentBytes {
		add("attachments_smaller", fmt.Sprintf("New chat attachments are limited to %d MB; existing ones stay.", t.AttachmentBytes>>20))
	}
	if lost(SCIM) {
		add("scim_stops", "SCIM provisioning stops; people already provisioned stay.")
	}
	if lost(AuditExport) {
		add("audit_export_stops", "Audit export is no longer available; the log itself is kept.")
	}
	if lost(CustomerHostedDataPlane) {
		add("data_plane_contractual", "The customer-hosted data plane is contractual; talk to us before changing this.")
	}
	return out
}
