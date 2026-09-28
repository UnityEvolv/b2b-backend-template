package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/notify"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/server"
)

// people is the user and organization services.
type people struct {
	mu      sync.Mutex
	persons map[uuid.UUID]notify.Person
	admins  []uuid.UUID
}

func (p *people) Person(_ context.Context, _, id uuid.UUID) (notify.Person, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.persons[id], nil
}

func (p *people) Members(context.Context, uuid.UUID, string) ([]uuid.UUID, error) {
	return p.admins, nil
}
func (p *people) OrgName(context.Context, uuid.UUID) (string, error) { return "Acme", nil }

// pushed is every push, by platform.
type pushed struct {
	mu   sync.Mutex
	sent map[string][]notify.Payload
}

type recorder struct {
	platform string
	into     *pushed
}

func (r recorder) Push(_ context.Context, _ string, p notify.Payload) error {
	if !p.Expires.IsZero() && p.Expires.Before(time.Now()) {
		return nil
	}
	r.into.mu.Lock()
	defer r.into.mu.Unlock()
	r.into.sent[r.platform] = append(r.into.sent[r.platform], p)
	return nil
}

func (p *pushed) take(platform string) []notify.Payload {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.sent[platform]
	p.sent[platform] = nil
	return out
}

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return time.Now()
	}
	return c.at
}

type notifyFixture struct {
	h      http.Handler
	router *notify.Router
	rdb    *redis.Client
	pool   *pgxpool.Pool
	issuer *stubissuer.Issuer
	people *people
	pushed *pushed
	clock  *clock
	grants authz.Static
	org    uuid.UUID
}

var linkKey = []byte("test-link-key")

func newNotify(t *testing.T) *notifyFixture {
	t.Helper()
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { rdb.Close() })

	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("notification")
	config, _ := pgxpool.ParseConfig(url)
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrator, _ := db.Migrator(stdlib.OpenDBFromPool(pool), service, migrations.FS)
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, _ := stubissuer.New("test", "unityofis")
	verifier := auth.NewStaticVerifier("test", "unityofis", issuer.PublicKeys())
	cluster := db.SingleShard(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &notifyFixture{rdb: rdb, pool: pool, issuer: issuer, people: &people{persons: map[uuid.UUID]notify.Person{}},
		pushed: &pushed{sent: map[string][]notify.Payload{}}, clock: &clock{}, grants: authz.Static{}, org: uuid.Must(uuid.NewV7())}
	pushers := notify.Pushers{"web": recorder{"web", f.pushed}, "android": recorder{"android", f.pushed}}
	f.router = notify.NewRouter(cluster, rdb, f.people, pushers, nil, notify.Links{App: "http://app.test", Admin: "http://admin.test", API: "http://api.test", Key: linkKey}, logger).WithClock(f.clock.now)
	srv := server.New(cluster, logger).WithNotifications(server.Notifications{Router: f.router, Authz: f.grants, VAPIDPublic: "public-key", LinkKey: linkKey})
	root := http.NewServeMux()
	api := srv.Handler(httpx.NewMux())
	root.Handle("POST /v1/unsubscribe/{token}", api)
	root.Handle("/", auth.Require(verifier, api))
	f.h = root
	return f
}

// person is a member with an email, in London, working from nine.
func (f *notifyFixture) person(t *testing.T, role authz.Role) (uuid.UUID, string) {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	london, _ := time.LoadLocation("Europe/London")
	f.people.mu.Lock()
	f.people.persons[id] = notify.Person{UserID: uuid.NewString(), Email: id.String() + "@example.org", Name: "P", Zone: london, WorkStart: 9 * 60, Active: true}
	f.people.mu.Unlock()
	f.grants[f.org.String()+"/"+id.String()] = authz.Grant{Role: role, Permissions: authz.Effective(role, authz.Defaults())}
	token, err := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: f.org.String(), MembershipID: id.String(), SessionID: uuid.NewString()}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

func (f *notifyFixture) do(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", uuid.NewString())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (f *notifyFixture) path(rest string) string { return "/v1/organizations/" + f.org.String() + rest }

// device registers a phone for the member.
func (f *notifyFixture) device(t *testing.T, token, platform string) {
	t.Helper()
	tok := "fcm-" + uuid.NewString()
	if platform == "web" {
		tok = `{"endpoint":"https://push.example.org/` + uuid.NewString() + `","keys":{"p256dh":"k","auth":"a"}}`
	}
	if code, out := f.do(t, http.MethodPost, f.path("/devices"), token, map[string]any{"platform": platform, "token": tok}); code != http.StatusCreated {
		t.Fatalf("device: %d %v", code, out)
	}
}

// looking sets what the member's app shows now, and when it was last open.
func (f *notifyFixture) looking(t *testing.T, id uuid.UUID, group string, seen time.Time) {
	t.Helper()
	ctx := context.Background()
	f.rdb.Del(ctx, notify.FocusKey(f.org, id))
	if group != "-" {
		f.rdb.HSet(ctx, notify.FocusKey(f.org, id), "socket-1", group)
	}
	f.rdb.Set(ctx, notify.SeenKey(f.org, id), strconv.FormatInt(seen.UnixMilli(), 10), time.Hour)
}

func (f *notifyFixture) emit(t *testing.T, ev notify.Event) {
	t.Helper()
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	ev.OrgID = f.org
	if err := f.router.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}

func (f *notifyFixture) outbox(t *testing.T, to uuid.UUID) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), "SELECT template FROM email_outbox WHERE org_id = $1 AND to_address = $2 ORDER BY created_at", f.org, to.String()+"@example.org")
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mention(to uuid.UUID, conv string) notify.Event {
	return notify.Event{Kind: "mention", Category: notify.Mention, Recipients: []uuid.UUID{to}, Link: "/chat/" + conv, Group: "conv:" + conv, Data: map[string]any{"by": "Ana", "where": "Design"}}
}

// The routing story's "done when".
func TestRouting(t *testing.T) {
	f := newNotify(t)
	reader, readerToken := f.person(t, authz.User)
	away, awayToken := f.person(t, authz.User)
	f.device(t, readerToken, "android")
	f.device(t, awayToken, "android")
	conv := uuid.NewString()

	// Reading the conversation: a feed entry, and nothing else.
	f.looking(t, reader, "conv:"+conv, time.Now())
	f.emit(t, mention(reader, conv))
	if got := f.pushed.take("android"); len(got) != 0 {
		t.Errorf("pushed to someone looking: %v", got)
	}
	if _, feed := f.do(t, http.MethodGet, f.path("/notifications"), readerToken, nil); feed["unread"].(float64) != 1 {
		t.Errorf("feed: %v", feed)
	}

	// On a backgrounded phone: one push. Three in two minutes: still one,
	// and one feed entry counting three.
	f.looking(t, away, "", time.Now().Add(-10*time.Minute))
	for range 3 {
		f.emit(t, mention(away, conv))
	}
	if got := f.pushed.take("android"); len(got) != 1 || got[0].Link != "/chat/"+conv {
		t.Errorf("pushes for three mentions: %v", got)
	}
	_, feed := f.do(t, http.MethodGet, f.path("/notifications"), awayToken, nil)
	entries := feed["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["count"].(float64) != 3 || feed["unread"].(float64) != 1 {
		t.Errorf("a batch is one entry: %v", feed)
	}
	// Away ten minutes: the mention waits for the digest, no email yet.
	if got := f.outbox(t, away); len(got) != 0 {
		t.Errorf("emailed someone away ten minutes: %v", got)
	}
	// The same event twice is one notification.
	ev := mention(away, uuid.NewString())
	ev.ID = "same"
	f.emit(t, ev)
	f.emit(t, ev)
	if got := f.pushed.take("android"); len(got) != 1 {
		t.Errorf("a duplicate event: %v", got)
	}

	// Opening the conversation reads its entries, everywhere.
	if code, out := f.do(t, http.MethodPost, f.path("/notifications/read"), awayToken, map[string]any{"about": "conv:" + conv}); code != http.StatusOK || out["unread"].(float64) != 1 {
		t.Errorf("read about: %d %v", code, out)
	}
	if code, out := f.do(t, http.MethodPost, f.path("/notifications/read"), awayToken, map[string]any{"all": true}); code != http.StatusOK || out["unread"].(float64) != 0 {
		t.Errorf("read all: %d %v", code, out)
	}
}

// A knock reaches a backgrounded phone while it is valid, and never a browser.
func TestKnocks(t *testing.T) {
	f := newNotify(t)
	id, token := f.person(t, authz.User)
	f.device(t, token, "android")
	f.device(t, token, "web")
	f.looking(t, id, "", time.Now().Add(-time.Minute))
	later := time.Now().Add(30 * time.Second)
	f.emit(t, notify.Event{Kind: "knock", Category: notify.Knock, Recipients: []uuid.UUID{id}, Link: "/offices/o", Group: "room:o:r", ExpiresAt: &later, Data: map[string]any{"by": "Ben", "room": "Design"}})
	if got := f.pushed.take("android"); len(got) != 1 || got[0].Expires.IsZero() {
		t.Errorf("knock push: %v", got)
	}
	if got := f.pushed.take("web"); len(got) != 0 {
		t.Errorf("a knock went to a browser: %v", got)
	}
	earlier := time.Now().Add(-time.Second)
	f.emit(t, notify.Event{Kind: "knock", Category: notify.Knock, Recipients: []uuid.UUID{id}, Link: "/offices/o", ExpiresAt: &earlier})
	if got := f.pushed.take("android"); len(got) != 0 {
		t.Errorf("an expired knock: %v", got)
	}
	// Never in the feed.
	if _, feed := f.do(t, http.MethodGet, f.path("/notifications"), token, nil); len(feed["entries"].([]any)) != 0 {
		t.Errorf("a knock in the feed: %v", feed)
	}
}

// A provider failure emails each admin once; quiet hours hold it.
func TestAdminEventsAndQuietHours(t *testing.T) {
	f := newNotify(t)
	a, _ := f.person(t, authz.Owner)
	b, bToken := f.person(t, authz.Admin)
	f.people.admins = []uuid.UUID{a, b}

	// b has quiet hours all day, every day but a minute.
	london, _ := time.LoadLocation("Europe/London")
	now := time.Now().In(london)
	start := (now.Hour()*60 + now.Minute() + 1439) % 1440
	end := (start + 5) % 1440
	code, out := f.do(t, http.MethodPut, f.path("/notification-preferences"), bToken, map[string]any{
		"channels": map[string]any{}, "push_previews": true, "muted": []string{},
		"quiet_hours": map[string]any{"enabled": true, "start_minute": start, "end_minute": end, "days": []int{1, 2, 3, 4, 5, 6, 7}},
	})
	if code != http.StatusOK {
		t.Fatalf("preferences: %d %v", code, out)
	}
	failing := notify.Event{ID: "provider-failing-1", Kind: "provider_failing", Category: notify.AdminProviders, Audience: "admins", Link: "/providers", Data: map[string]any{"heading": "LiveKit is not answering"}}
	f.emit(t, failing)
	f.emit(t, failing)
	if got := f.outbox(t, a); len(got) != 1 || got[0] != "notification" {
		t.Errorf("admin a emails: %v", got)
	}
	if got := f.outbox(t, b); len(got) != 0 {
		t.Errorf("emailed during quiet hours: %v", got)
	}
	// When quiet hours end, what they held goes.
	f.clock.mu.Lock()
	f.clock.at = time.Now().Add(10 * time.Minute)
	f.clock.mu.Unlock()
	// Their end, moved to now; the provenance trigger needs an actor.
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tx.Exec(context.Background(), "SELECT set_config('app.actor', 'test', true)")
	if _, err := tx.Exec(context.Background(), "UPDATE held SET release_at = now() - interval '1 second' WHERE org_id = $1", f.org); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.router.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.outbox(t, b); len(got) != 1 {
		t.Errorf("released after quiet hours: %v", got)
	}
}

// Mentions that were not emailed at once arrive as one digest at the
// person's time, and a digest with nothing in it is not sent.
func TestDigest(t *testing.T) {
	f := newNotify(t)
	id, _ := f.person(t, authz.User)
	f.looking(t, id, "", time.Now().Add(-5*time.Minute))
	f.emit(t, mention(id, uuid.NewString()))
	f.emit(t, mention(id, uuid.NewString()))
	if got := f.outbox(t, id); len(got) != 0 {
		t.Fatalf("emailed at once: %v", got)
	}
	london, _ := time.LoadLocation("Europe/London")
	tomorrow := time.Now().In(london).AddDate(0, 0, 1)
	f.clock.mu.Lock()
	f.clock.at = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 9, 30, 0, 0, london)
	f.clock.mu.Unlock()
	if err := f.router.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.outbox(t, id); len(got) != 1 || got[0] != "digest" {
		t.Errorf("digest: %v", got)
	}
	if err := f.router.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.outbox(t, id); len(got) != 1 {
		t.Errorf("a second digest: %v", got)
	}
}

// Preferences, the test button, one-click unsubscribe, devices and the push key.
func TestPreferencesAndDevices(t *testing.T) {
	f := newNotify(t)
	id, token := f.person(t, authz.User)
	code, prefs := f.do(t, http.MethodGet, f.path("/notification-preferences"), token, nil)
	if code != http.StatusOK || !prefs["channels"].(map[string]any)["mention"].(map[string]any)["push"].(bool) || prefs["channels"].(map[string]any)["room_message"].(map[string]any)["push"].(bool) {
		t.Fatalf("defaults: %d %v", code, prefs)
	}
	if code, _ := f.do(t, http.MethodPut, f.path("/notification-preferences"), token, map[string]any{
		"channels": map[string]any{"nonsense": map[string]any{"in_app": true, "push": true, "email": true}}, "push_previews": true, "muted": []string{},
		"quiet_hours": map[string]any{"enabled": false, "start_minute": 0, "end_minute": 0, "days": []int{}},
	}); code != http.StatusBadRequest {
		t.Errorf("an unknown category: %d", code)
	}
	// Turning push off for room messages stops them; mentions still arrive.
	f.device(t, token, "android")
	f.do(t, http.MethodPut, f.path("/notification-preferences"), token, map[string]any{
		"channels": map[string]any{"room_message": map[string]any{"in_app": true, "push": false, "email": false}}, "push_previews": true, "muted": []string{},
		"quiet_hours": map[string]any{"enabled": false, "start_minute": 0, "end_minute": 0, "days": []int{}},
	})
	f.looking(t, id, "-", time.Now().Add(-time.Minute))
	conv := uuid.NewString()
	f.emit(t, notify.Event{Kind: "room_message", Category: notify.RoomMessage, Recipients: []uuid.UUID{id}, Link: "/chat/" + conv, Group: "conv:x" + conv})
	if got := f.pushed.take("android"); len(got) != 0 {
		t.Errorf("room message pushed with push off: %v", got)
	}
	f.emit(t, mention(id, conv))
	if got := f.pushed.take("android"); len(got) != 1 {
		t.Errorf("a mention with push on: %v", got)
	}
	// The test button: exactly one on the chosen channel.
	if code, out := f.do(t, http.MethodPost, f.path("/notification-preferences/test"), token, map[string]any{"channel": "push"}); code != http.StatusAccepted || out["delivered"].(float64) != 1 {
		t.Errorf("test push: %d %v", code, out)
	}
	if got := f.pushed.take("android"); len(got) != 1 {
		t.Errorf("test pushes: %v", got)
	}
	if code, _ := f.do(t, http.MethodPost, f.path("/notification-preferences/test"), token, map[string]any{"channel": "email"}); code != http.StatusAccepted || len(f.outbox(t, id)) != 1 {
		t.Errorf("test email: %d %v", code, f.outbox(t, id))
	}
	// One-click unsubscribe, with no sign-in.
	link := notify.UnsubscribeToken(linkKey, f.org, id, notify.Mention)
	if code, out := f.do(t, http.MethodPost, "/v1/unsubscribe/"+link, "", nil); code != http.StatusOK || out["category"] != "mention" {
		t.Fatalf("unsubscribe: %d %v", code, out)
	}
	_, prefs = f.do(t, http.MethodGet, f.path("/notification-preferences"), token, nil)
	if prefs["channels"].(map[string]any)["mention"].(map[string]any)["email"].(bool) {
		t.Errorf("mention email still on: %v", prefs)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/unsubscribe/"+link+"x", "", nil); code != http.StatusBadRequest {
		t.Errorf("a forged link: %d", code)
	}
	// A web subscription must be one; the push key is public.
	if code, _ := f.do(t, http.MethodPost, f.path("/devices"), token, map[string]any{"platform": "web", "token": "not json"}); code != http.StatusBadRequest {
		t.Errorf("a bad subscription: %d", code)
	}
	// Only an Owner sets the org's defaults.
	if code, _ := f.do(t, http.MethodPut, f.path("/notification-settings"), token, map[string]any{"channels": map[string]any{}, "previews_allowed": false}); code != http.StatusForbidden {
		t.Errorf("a user setting org defaults: %d", code)
	}
	_, owner := f.person(t, authz.Owner)
	if code, out := f.do(t, http.MethodPut, f.path("/notification-settings"), owner, map[string]any{"channels": map[string]any{}, "previews_allowed": false}); code != http.StatusOK || out["previews_allowed"] != false {
		t.Errorf("owner: %d %v", code, out)
	}
	if _, prefs := f.do(t, http.MethodGet, f.path("/notification-preferences"), token, nil); prefs["push_previews"] != false {
		t.Errorf("previews forced off: %v", prefs)
	}
}
