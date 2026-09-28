package notify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Event is something that happened that people may be told about. Its owner
// emits it; this package decides the rest.
type Event struct {
	ID         string         `json:"id"`
	OrgID      uuid.UUID      `json:"org_id"`
	Kind       string         `json:"kind"`
	Category   Category       `json:"category"`
	Recipients []uuid.UUID    `json:"recipients"`
	Audience   string         `json:"audience,omitempty"`
	Actor      *uuid.UUID     `json:"actor,omitempty"`
	Link       string         `json:"link"`
	Group      string         `json:"group,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	Preview    string         `json:"preview,omitempty"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
}

// Validate is nil when the event can be routed.
func (e Event) Validate() error {
	switch {
	case e.ID == "" || len(e.ID) > 200:
		return errors.New("an id")
	case e.OrgID == uuid.Nil:
		return errors.New("an org")
	case e.Kind == "" || len(e.Kind) > 60:
		return errors.New("a kind")
	case !e.Category.Valid():
		return errors.New("a category")
	case len(e.Recipients) == 0 && e.Audience == "":
		return errors.New("recipients or an audience")
	case len(e.Recipients) > 5000:
		return errors.New("at most 5000 recipients")
	case e.Link == "" || len(e.Link) > 500 || !strings.HasPrefix(e.Link, "/"):
		return errors.New("a link, a path in the app")
	case len(e.Group) > 200 || len(e.Preview) > 300:
		return errors.New("a shorter group or preview")
	}
	return nil
}

// Person is what routing needs to know about a recipient.
type Person struct {
	UserID string
	Email  string
	Name   string
	Zone   *time.Location
	// Start of their working day, minutes after midnight in their zone.
	WorkStart int
	Active    bool
}

// Directory answers who people are: the user and organization services.
type Directory interface {
	Person(ctx context.Context, org, membership uuid.UUID) (Person, error)
	// Members is everyone in the org an audience names ("admins", "billing").
	Members(ctx context.Context, org uuid.UUID, audience string) ([]uuid.UUID, error)
	OrgName(ctx context.Context, org uuid.UUID) (string, error)
}

// Live tells a person's open apps about a new feed entry, over the realtime
// service's sockets.
type Live interface {
	Feed(ctx context.Context, org uuid.UUID, recipients []uuid.UUID) error
}

// Links make the absolute links an email carries.
type Links struct {
	// App is the employee app's origin; Admin the admin app's.
	App, Admin string
	// API is this service's public base, where the one-click unsubscribe
	// endpoint is: behind the load balancer's /notification, or its own port
	// on a laptop.
	API string
	// Key signs unsubscribe tokens.
	Key []byte
}

// Router routes events. Everything it keeps between events is in Redis, with
// a time to live; the database holds only the feed, preferences, devices and
// what quiet hours hold.
type Router struct {
	cluster *db.Cluster
	redis   redis.Cmdable
	people  Directory
	pushers Pushers
	live    Live
	links   Links
	logger  *slog.Logger
	now     func() time.Time
}

// NewRouter is the router.
func NewRouter(cluster *db.Cluster, rdb redis.Cmdable, people Directory, pushers Pushers, live Live, links Links, logger *slog.Logger) *Router {
	return &Router{cluster: cluster, redis: rdb, people: people, pushers: pushers, live: live, links: links, logger: logger, now: time.Now}
}

// WithClock is r reading the time from now: tests.
func (r *Router) WithClock(now func() time.Time) *Router {
	r.now = now
	return r
}

// Redis keys. Focus and seen are written by the realtime service, which knows
// what each person's apps are showing.
func dedupeKey(org uuid.UUID, id string, to uuid.UUID) string {
	return fmt.Sprintf("notify:dedupe:%s:%s:%s", org, id, to)
}
func batchKey(org, to uuid.UUID, group string) string {
	return fmt.Sprintf("notify:batch:%s:%s:%s", org, to, group)
}

// FocusKey is a hash, socket => what that socket is showing ("" when the app
// is in the background). SeenKey is when the person last had the app open.
func FocusKey(org, to uuid.UUID) string { return fmt.Sprintf("unityofis:focus:%s:%s", org, to) }
func SeenKey(org, to uuid.UUID) string  { return fmt.Sprintf("unityofis:seen:%s:%s", org, to) }

const dedupeFor = 10 * time.Minute

// Handle routes one event to each of its recipients.
func (r *Router) Handle(ctx context.Context, ev Event) error {
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	if err := ev.Validate(); err != nil {
		return err
	}
	recipients := ev.Recipients
	if ev.Audience != "" {
		var err error
		if recipients, err = r.people.Members(ctx, ev.OrgID, ev.Audience); err != nil {
			return err
		}
	}
	now := r.now()
	if ev.ExpiresAt != nil && !ev.ExpiresAt.After(now) {
		return nil
	}
	// Who did it, by name, when the emitter did not say: a service that
	// knows only memberships.
	if _, named := ev.Data["by"]; !named && ev.Actor != nil {
		if actor, err := r.people.Person(ctx, ev.OrgID, *ev.Actor); err == nil && actor.Name != "" {
			data := map[string]any{"by": actor.Name}
			for k, v := range ev.Data {
				data[k] = v
			}
			ev.Data = data
		}
	}
	var fed []uuid.UUID
	for _, to := range recipients {
		if ev.Actor != nil && *ev.Actor == to {
			continue
		}
		// The same event to the same person is one notification, whichever
		// node or path it arrived by.
		first, err := r.redis.SetNX(ctx, dedupeKey(ev.OrgID, ev.ID, to), 1, dedupeFor).Result()
		if err != nil {
			return err
		}
		if !first {
			continue
		}
		inFeed, err := r.route(ctx, ev, to, now)
		if err != nil {
			r.logger.Error("notification not routed", "org_id", ev.OrgID, "membership_id", to, "kind", ev.Kind, "error", err)
			continue
		}
		if inFeed {
			fed = append(fed, to)
		}
	}
	if len(fed) > 0 && r.live != nil {
		if err := r.live.Feed(ctx, ev.OrgID, fed); err != nil {
			r.logger.Warn("feed not pushed live", "org_id", ev.OrgID, "error", err)
		}
	}
	return nil
}

// settings is one recipient's resolved preferences.
type settings struct {
	channels   map[Category]Channels
	previews   bool
	quiet      Quiet
	muted      []uuid.UUID
	digestMin  *int
	lastDigest time.Time
}

func (r *Router) settings(ctx context.Context, org, to uuid.UUID, zone *time.Location) (settings, error) {
	var (
		p   store.Preference
		o   store.OrgSetting
		has bool
	)
	err := r.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		p, err = q.GetPreferences(ctx, store.GetPreferencesParams{OrgID: org, MembershipID: to})
		switch {
		case err == nil:
			has = true
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		o, err = q.GetOrgSettings(ctx, org)
		if errors.Is(err, pgx.ErrNoRows) {
			o = store.OrgSetting{Channels: []byte("{}"), PreviewsAllowed: true}
			return nil
		}
		return err
	})
	if err != nil {
		return settings{}, err
	}
	s := settings{previews: o.PreviewsAllowed}
	if !has {
		s.channels = Resolve(nil, o.Channels)
		return s, nil
	}
	s.channels = Resolve(p.Channels, o.Channels)
	s.previews = s.previews && p.PushPreviews
	s.quiet = Quiet{Enabled: p.QuietEnabled, Start: int(p.QuietStartMinute), End: int(p.QuietEndMinute), Days: p.QuietDays, Zone: zone}
	s.muted = p.Muted
	if p.DigestMinute.Valid {
		m := int(p.DigestMinute.Int32)
		s.digestMin = &m
	}
	if p.LastDigestAt.Valid {
		s.lastDigest = p.LastDigestAt.Time
	}
	return s, nil
}

// looking is whether any of the person's apps is showing what the event is
// about right now, and how long since any was open.
func (r *Router) looking(ctx context.Context, org, to uuid.UUID, group string, now time.Time) (bool, time.Duration, error) {
	shown, err := r.redis.HVals(ctx, FocusKey(org, to)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, 0, err
	}
	away := 365 * 24 * time.Hour
	if seen, err := r.redis.Get(ctx, SeenKey(org, to)).Result(); err == nil {
		if ms, err := strconv.ParseInt(seen, 10, 64); err == nil {
			away = now.Sub(time.UnixMilli(ms))
		}
	}
	if len(shown) > 0 {
		for _, s := range shown {
			if s != "" {
				away = 0
			}
		}
	}
	if group == "" {
		return false, away, nil
	}
	// A socket may show several things at once, comma separated: the room on
	// the map and a conversation in the sidebar.
	for _, s := range shown {
		if slices.Contains(strings.Split(s, ","), group) {
			return true, away, nil
		}
	}
	return false, away, nil
}

// route is one event for one person. It reports whether a feed entry was
// written or grown.
func (r *Router) route(ctx context.Context, ev Event, to uuid.UUID, now time.Time) (bool, error) {
	person, err := r.people.Person(ctx, ev.OrgID, to)
	if err != nil {
		return false, err
	}
	if !person.Active {
		return false, nil
	}
	s, err := r.settings(ctx, ev.OrgID, to, person.Zone)
	if err != nil {
		return false, err
	}
	if conv, ok := strings.CutPrefix(ev.Group, "conv:"); ok {
		if id, err := uuid.Parse(conv); err == nil && slices.Contains(s.muted, id) {
			return false, nil
		}
	}
	ch := s.channels[ev.Category]
	looking, away, err := r.looking(ctx, ev.OrgID, to, ev.Group, now)
	if err != nil {
		return false, err
	}

	var entry *store.FeedEntry
	if ch.InApp && ev.Category != Knock {
		e, err := r.feed(ctx, ev, to, now)
		if err != nil {
			return false, err
		}
		entry = &e
		r.count(ctx, ev.OrgID, "in_app", 1, 0)
	}
	// Somebody looking at the thing has already seen it: no push, no email.
	if looking {
		return entry != nil, nil
	}

	if ch.Push {
		batched := true
		if ev.Category.Batched() && ev.Group != "" {
			// Three mentions in two minutes are one push.
			batched, err = r.redis.SetNX(ctx, batchKey(ev.OrgID, to, ev.Group), 1, BatchWindow).Result()
			if err != nil {
				return entry != nil, err
			}
		}
		if batched {
			p := r.payload(ev, entry, s.previews)
			if until, quiet := s.quiet.Until(now); quiet && ev.Category != Knock {
				r.hold(ctx, ev.OrgID, to, "push", p, until, ev.ExpiresAt)
			} else {
				r.PushTo(ctx, ev.OrgID, to, ev.Category, p)
			}
		}
	}

	// Email: now for what must be known now, else the digest collects it.
	if ch.Email && entry != nil && Immediate(ev.Category, away) {
		if until, quiet := s.quiet.Until(now); quiet {
			r.hold(ctx, ev.OrgID, to, "email", emailHeld{EntryID: entry.ID}, until, ev.ExpiresAt)
		} else if err := r.emailEntry(ctx, ev.OrgID, to, person, *entry); err != nil {
			r.logger.Warn("notification email not queued", "org_id", ev.OrgID, "membership_id", to, "error", err)
		}
	}
	return entry != nil, nil
}

// item is one event as a batch keeps it.
func item(ev Event, now time.Time) []byte {
	raw, _ := json.Marshal(map[string]any{"kind": ev.Kind, "data": ev.Data, "link": ev.Link, "at": now.UTC()})
	return raw
}

// feed writes the entry, or grows the open batch of its group.
func (r *Router) feed(ctx context.Context, ev Event, to uuid.UUID, now time.Time) (store.FeedEntry, error) {
	data := map[string]any{}
	for k, v := range ev.Data {
		data[k] = v
	}
	rawData, err := json.Marshal(data)
	if err != nil {
		return store.FeedEntry{}, err
	}
	var entry store.FeedEntry
	err = r.cluster.Tx(ctx, ev.OrgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if ev.Category.Batched() && ev.Group != "" {
			open, err := q.OpenBatch(ctx, store.OpenBatchParams{OrgID: ev.OrgID, MembershipID: to, GroupKey: pgtype.Text{String: ev.Group, Valid: true}, Since: now.Add(-BatchWindow)})
			if err == nil {
				entry, err = q.GrowBatch(ctx, store.GrowBatchParams{
					OrgID: ev.OrgID, ID: open.ID, Data: rawData, Link: ev.Link, OccurredAt: now,
					Item: []byte("[" + string(item(ev, now)) + "]"), ExpiresAt: now.Add(FeedLife),
				})
				return err
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		entry, err = q.InsertFeedEntry(ctx, store.InsertFeedEntryParams{
			OrgID: ev.OrgID, ID: id, MembershipID: to, Category: string(ev.Category), Kind: ev.Kind,
			Data: rawData, Link: ev.Link, GroupKey: pgtype.Text{String: ev.Group, Valid: ev.Group != ""},
			Items: []byte("[" + string(item(ev, now)) + "]"), OccurredAt: now, ExpiresAt: now.Add(FeedLife),
		})
		return err
	})
	return entry, err
}

// payload is the push for an event: the words, and the preview only where
// the person and their org allow it.
func (r *Router) payload(ev Event, entry *store.FeedEntry, previews bool) Payload {
	title, body := Words(ev.Kind, ev.Data, 1)
	if entry != nil && entry.Count > 1 {
		title, body = Words(ev.Kind, ev.Data, int(entry.Count))
	}
	if previews && ev.Preview != "" {
		body = ev.Preview
	}
	p := Payload{Title: title, Body: body, Category: ev.Category, Link: ev.Link, Collapse: ev.Group}
	if ev.ExpiresAt != nil {
		p.Expires = *ev.ExpiresAt
	}
	return p
}

// PushTo sends p to every device the person has for category: knocks only to
// phones, since a desktop or a browser tab has the office open or no need.
func (r *Router) PushTo(ctx context.Context, org, to uuid.UUID, category Category, p Payload) int {
	var devices []store.Device
	err := r.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		devices, err = store.New(tx).DevicesOf(ctx, store.DevicesOfParams{OrgID: org, MembershipID: to})
		return err
	})
	if err != nil {
		r.logger.Error("devices not read", "org_id", org, "error", err)
		return 0
	}
	sent, failed := 0, 0
	for _, d := range devices {
		if category == Knock && d.Platform == "web" {
			continue
		}
		pusher, ok := r.pushers[d.Platform]
		if !ok {
			continue
		}
		err := pusher.Push(ctx, d.Token, p)
		if errors.Is(err, ErrTransient) {
			err = pusher.Push(ctx, d.Token, p)
		}
		switch {
		case err == nil:
			sent++
		case errors.Is(err, ErrInvalidToken):
			failed++
			// A dead token goes at once, so the next send does not try it.
			_ = r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
				return store.New(tx).DeleteDevice(ctx, store.DeleteDeviceParams{OrgID: org, ID: d.ID})
			})
		default:
			failed++
		}
	}
	r.count(ctx, org, "push", sent, failed)
	return sent
}

type emailHeld struct {
	EntryID uuid.UUID `json:"entry_id"`
}

// hold keeps a push or email until quiet hours end.
func (r *Router) hold(ctx context.Context, org, to uuid.UUID, channel string, what any, until time.Time, expires *time.Time) {
	raw, err := json.Marshal(what)
	if err != nil {
		return
	}
	id, _ := uuid.NewV7()
	exp := pgtype.Timestamptz{}
	if expires != nil {
		exp = pgtype.Timestamptz{Time: *expires, Valid: true}
	}
	err = r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		return store.New(tx).Hold(ctx, store.HoldParams{OrgID: org, ID: id, MembershipID: to, Channel: channel, Notification: raw, ReleaseAt: until, ExpiresAt: exp})
	})
	if err != nil {
		r.logger.Error("notification not held", "org_id", org, "error", err)
	}
}

// emailEntry queues one feed entry as an email now, and marks it emailed so
// the digest does not repeat it.
func (r *Router) emailEntry(ctx context.Context, org, to uuid.UUID, person Person, entry store.FeedEntry) error {
	if person.Email == "" {
		return nil
	}
	var data map[string]any
	_ = json.Unmarshal(entry.Data, &data)
	heading, line := Words(entry.Kind, data, int(entry.Count))
	category := Category(entry.Category)
	return r.queueEmail(ctx, org, to, person, category, "notification", map[string]any{
		"heading": heading, "line": line, "link": r.appLink(category, entry.Link),
	}, []uuid.UUID{entry.ID})
}

func (r *Router) appLink(category Category, path string) string {
	if category.Admin() && r.links.Admin != "" {
		return strings.TrimRight(r.links.Admin, "/") + path
	}
	return strings.TrimRight(r.links.App, "/") + path
}

// queueEmail renders a notification email into the outbox, with its
// unsubscribe link, and marks the entries it carries emailed.
func (r *Router) queueEmail(ctx context.Context, org, to uuid.UUID, person Person, category Category, template string, data map[string]any, entries []uuid.UUID) error {
	orgName, err := r.people.OrgName(ctx, org)
	if err != nil {
		return err
	}
	token := UnsubscribeToken(r.links.Key, org, to, category)
	data["preferences"] = strings.TrimRight(r.links.App, "/") + "/settings/notifications?unsubscribe=" + token
	unsubscribe := strings.TrimRight(r.links.API, "/") + "/v1/unsubscribe/" + token
	rendered, err := email.Render(template, orgName, data)
	if err != nil {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	err = r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		suppressed, err := q.IsSuppressed(ctx, person.Email)
		if err != nil {
			return err
		}
		state := "queued"
		if suppressed {
			state = "suppressed"
		}
		if _, err := q.QueueEmail(ctx, store.QueueEmailParams{
			OrgID: org, ID: id, ToAddress: person.Email, Template: template,
			Subject: rendered.Subject, HtmlBody: rendered.HTML, TextBody: rendered.Text,
			State: state, NextAttemptAt: r.now().UTC(), UnsubscribeUrl: pgtype.Text{String: unsubscribe, Valid: true},
		}); err != nil {
			return err
		}
		return q.MarkEmailed(ctx, store.MarkEmailedParams{OrgID: org, Ids: entries})
	})
	if err == nil {
		r.count(ctx, org, "email", 1, 0)
	}
	return err
}

// count adds to the day's totals. Counts, never a log.
func (r *Router) count(ctx context.Context, org uuid.UUID, channel string, sent, failed int) {
	if sent == 0 && failed == 0 {
		return
	}
	day := r.now().UTC()
	err := r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		return store.New(tx).Count(ctx, store.CountParams{
			OrgID: org, Day: pgtype.Date{Time: time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC), Valid: true},
			Channel: channel, Sent: int32(sent), Failed: int32(failed),
		})
	})
	if err != nil {
		r.logger.Warn("notification count not kept", "org_id", org, "error", err)
	}
}

// TokenHash is how a device token is looked up without being an index key.
func TokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Test sends one notification on one channel to the person, whatever their
// preferences say: the "is it working" button. It answers how many devices a
// push reached, or 1 for the feed and email.
func (r *Router) Test(ctx context.Context, org, to uuid.UUID, channel string) (int, error) {
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	now := r.now()
	ev := Event{ID: "test:" + uuid.NewString(), OrgID: org, Kind: "test", Category: RoomActivity, Link: "/settings/notifications"}
	switch channel {
	case "in_app":
		if _, err := r.feed(ctx, ev, to, now); err != nil {
			return 0, err
		}
		if r.live != nil {
			_ = r.live.Feed(ctx, org, []uuid.UUID{to})
		}
		return 1, nil
	case "push":
		title, body := Words("test", nil, 1)
		return r.PushTo(ctx, org, to, RoomActivity, Payload{Title: title, Body: body, Category: RoomActivity, Link: ev.Link, Expires: now.Add(time.Hour)}), nil
	case "email":
		person, err := r.people.Person(ctx, org, to)
		if err != nil {
			return 0, err
		}
		heading, line := Words("test", nil, 1)
		if err := r.queueEmail(ctx, org, to, person, RoomActivity, "notification", map[string]any{
			"heading": heading, "line": line, "link": r.appLink(RoomActivity, ev.Link),
		}, []uuid.UUID{}); err != nil {
			return 0, err
		}
		return 1, nil
	}
	return 0, fmt.Errorf("no channel %q", channel)
}

// Live tells one person's open apps their feed changed. Best effort.
func (r *Router) Live(ctx context.Context, org, to uuid.UUID) {
	if r.live == nil {
		return
	}
	if err := r.live.Feed(ctx, org, []uuid.UUID{to}); err != nil {
		r.logger.Warn("feed not pushed live", "org_id", org, "error", err)
	}
}
