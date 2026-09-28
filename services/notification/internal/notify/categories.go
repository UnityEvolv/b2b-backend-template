// Package notify decides who is told about what, how, and whether at all
// (UO-175): intake, routing by preference, quiet hours, suppression while
// someone is looking, dedupe and batching, and delivery to the feed, push
// and email. Nothing else in the platform sends a notification.
package notify

import (
	"encoding/json"
	"slices"
	"time"
)

// Category is what a notification is about, the rows of the preferences grid.
type Category string

const (
	Mention          Category = "mention"
	DirectMessage    Category = "direct_message"
	RoomMessage      Category = "room_message"
	RoomActivity     Category = "room_activity"
	Knock            Category = "knock"
	Meeting          Category = "meeting"
	AdminProviders   Category = "admin_providers"
	AdminBilling     Category = "admin_billing"
	AdminTemplates   Category = "admin_templates"
	AdminMarketplace Category = "admin_marketplace"
	AdminDirectory   Category = "admin_directory"
)

// Categories is every category, in the order the preferences page lists them.
var Categories = []Category{Mention, DirectMessage, RoomMessage, RoomActivity, Knock, Meeting, AdminProviders, AdminBilling, AdminTemplates, AdminMarketplace, AdminDirectory}

// Valid reports whether c is a category.
func (c Category) Valid() bool { return slices.Contains(Categories, c) }

// Admin reports whether c is one of the admin categories.
func (c Category) Admin() bool {
	return c == AdminProviders || c == AdminBilling || c == AdminTemplates || c == AdminMarketplace || c == AdminDirectory
}

// Channels is where one category goes.
type Channels struct {
	InApp bool `json:"in_app"`
	Push  bool `json:"push"`
	Email bool `json:"email"`
}

// Defaults is what a person gets without visiting the preferences page:
// mentions and direct messages everywhere, room messages and activity in the
// app only, admin events in the app and by email, and knocks by push only.
var Defaults = map[Category]Channels{
	Mention:       {InApp: true, Push: true, Email: true},
	DirectMessage: {InApp: true, Push: true, Email: true},
	RoomMessage:   {InApp: true},
	RoomActivity:  {InApp: true},
	Knock:         {Push: true},
	// A few minutes before a meeting, quietly: in the app and on the phone.
	Meeting:          {InApp: true, Push: true},
	AdminProviders:   {InApp: true, Email: true},
	AdminBilling:     {InApp: true, Email: true},
	AdminTemplates:   {InApp: true, Email: true},
	AdminMarketplace: {InApp: true, Email: true},
	AdminDirectory:   {InApp: true, Email: true},
}

// Resolve is the channels for every category: the person's choice, else the
// org's default for new members, else the platform's. Knocks never reach the
// feed or email, whatever is stored.
func Resolve(person, org []byte) map[Category]Channels {
	var mine, theirs map[Category]Channels
	_ = json.Unmarshal(person, &mine)
	_ = json.Unmarshal(org, &theirs)
	out := make(map[Category]Channels, len(Categories))
	for _, c := range Categories {
		ch := Defaults[c]
		if v, ok := theirs[c]; ok {
			ch = v
		}
		if v, ok := mine[c]; ok {
			ch = v
		}
		if c == Knock {
			ch = Channels{Push: ch.Push}
		}
		out[c] = ch
	}
	return out
}

// Batched categories collapse within a window into one feed entry and one push.
func (c Category) Batched() bool {
	return c == Mention || c == DirectMessage || c == RoomMessage
}

// BatchWindow is how long items of one conversation collapse together.
const BatchWindow = 3 * time.Minute

// FeedLife is how long an entry stays in the feed.
const FeedLife = 30 * 24 * time.Hour

// OfflineForEmail is how long someone must have been away before a mention or
// direct message is emailed at once rather than waiting for the digest.
const OfflineForEmail = time.Hour

// Immediate reports whether an email for c goes now rather than in the digest,
// given how long the person has been away.
func Immediate(c Category, away time.Duration) bool {
	if c.Admin() {
		return true
	}
	if c == Mention || c == DirectMessage {
		return away > OfflineForEmail
	}
	return false
}
