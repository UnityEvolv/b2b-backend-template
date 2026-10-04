package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
)

// The example product through every seam, against the template's services
// run unchanged. Each subtest is one seam; they share the stack and run in
// order, because starting it is the slow part.
func TestProjectsThroughEverySeam(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()

	operator, status := s.token(map[string]any{"user_id": uuid.NewString(), "org_id": auth.PlatformOrg, "membership_id": uuid.NewString()})
	if status != http.StatusOK {
		t.Fatalf("operator token: %d", status)
	}
	acme := s.org(operator, "Acme", "free")
	owner := s.member(acme, "owner@acme.test", "owner")
	admin := s.member(acme, "admin@acme.test", "admin")
	colleague := s.member(acme, "colleague@acme.test", "user")

	projects := s.url(product.Name) + "/v1/organizations/" + acme.String() + "/projects"
	create := func(p *person, name, key string) reply {
		t.Helper()
		return s.call(http.MethodPost, projects, p.token, map[string]any{"name": name}, key)
	}
	var (
		shared   string // a project shared with colleague, with a cover
		coverPNG []byte
	)

	t.Run("schema: its own schema and role, from its own migrate command", func(t *testing.T) {
		admin := connect(t, s.dbURL, nil)
		problems, err := db.CheckConventions(ctx, admin, product.Service.Schema)
		if err != nil || len(problems) > 0 {
			t.Errorf("table conventions: %v %v", problems, err)
		}
		var owner string
		if err := admin.QueryRow(ctx, "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1", product.Service.Schema).Scan(&owner); err != nil || owner != "svc_projects" {
			t.Errorf("schema owner %q (%v)", owner, err)
		}
		// Its role reaches its own schema and nothing else.
		own := connect(t, s.dbURL, &product.Service)
		if _, err := own.Exec(ctx, "SELECT count(*) FROM projects"); err != nil {
			t.Errorf("own table: %v", err)
		}
		_, err = own.Exec(ctx, "SELECT count(*) FROM organization.organizations")
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("another service's schema: %v", err)
		}
	})

	t.Run("service tokens: a known service both ways, through DATA_OWNERS", func(t *testing.T) {
		// The identity service mints the product a token only because
		// DATA_OWNERS names it; a service nobody registered gets none.
		if _, status := s.token(map[string]any{"service": product.Name}); status != http.StatusOK {
			t.Errorf("a token for projects: %d", status)
		}
		if _, status := s.token(map[string]any{"service": "widgets"}); status != http.StatusBadRequest {
			t.Errorf("a token for an unknown service: %d", status)
		}
		// The template's services take the product's token...
		if r := s.call(http.MethodGet, s.url("organization")+"/v1/internal/organizations/"+acme.String()+"/plan", s.serviceToken(product.Name), nil); r.status != http.StatusOK || r.str("plan") != "free" {
			t.Errorf("organization, as projects: %s", r)
		}
		// ...and the product takes theirs, from the right one only.
		data := s.url(product.Name) + "/v1/internal/organizations/" + acme.String() + "/data"
		if r := s.call(http.MethodGet, data, s.serviceToken("organization"), nil); r.status != http.StatusOK || r.str("service") != product.Name {
			t.Errorf("projects, as organization: %s", r)
		}
		if r := s.call(http.MethodGet, data, s.serviceToken("billing"), nil); r.status != http.StatusForbidden {
			t.Errorf("projects, as billing: %s", r)
		}
		if r := s.call(http.MethodGet, data, owner.token, nil); r.status != http.StatusForbidden {
			t.Errorf("projects, as a person: %s", r)
		}
	})

	t.Run("permissions: the projects group, configured per org, enforced by the API", func(t *testing.T) {
		groups := s.call(http.MethodGet, s.url("authorization")+"/v1/permission-groups", owner.token, nil)
		if !strings.Contains(string(groups.raw), `"key":"projects"`) {
			t.Fatalf("the authorization service does not list projects: %s", groups)
		}
		if r := create(colleague, "Nope", "colleague-1"); r.status != http.StatusForbidden || r.code() != "forbidden" {
			t.Errorf("a User creates: %s", r)
		}
		first := create(admin, "Apollo", "admin-1")
		if first.status != http.StatusCreated {
			t.Fatalf("an Admin creates by default: %s", first)
		}
		one := projects + "/" + first.str("id")

		// The Owner takes projects away from Admins in this org...
		permissions := s.url("authorization") + "/v1/organizations/" + acme.String() + "/permissions"
		without := map[string]any{"admin": []string{"users", "audit", "sso"}, "billing_admin": []string{"billing"}}
		if r := s.call(http.MethodPut, permissions, owner.token, without); r.status != http.StatusOK {
			t.Fatalf("configure: %s", r)
		}
		if r := create(admin, "Nope", "admin-2"); r.status != http.StatusForbidden {
			t.Errorf("an Admin without projects creates: %s", r)
		}
		if r := s.call(http.MethodPatch, one, admin.token, map[string]any{"name": "Nope"}); r.status != http.StatusForbidden {
			t.Errorf("an Admin without projects renames: %s", r)
		}
		if r := s.call(http.MethodDelete, one, admin.token, nil); r.status != http.StatusForbidden {
			t.Errorf("an Admin without projects deletes: %s", r)
		}
		// Reading needs no group.
		if r := s.call(http.MethodGet, one, colleague.token, nil); r.status != http.StatusOK {
			t.Errorf("a User reads: %s", r)
		}
		// ...and gives it back; the next request sees it.
		with := map[string]any{"admin": []string{"users", "audit", "sso", "projects"}, "billing_admin": []string{"billing"}}
		if r := s.call(http.MethodPut, permissions, owner.token, with); r.status != http.StatusOK {
			t.Fatalf("configure: %s", r)
		}
		if r := s.call(http.MethodPatch, one, admin.token, map[string]any{"description": "To the moon"}); r.status != http.StatusOK || r.str("description") != "To the moon" {
			t.Errorf("an Admin with projects again: %s", r)
		}
		// Another org's token reaches nothing here.
		other := &person{membership: uuid.New(), user: uuid.New(), org: uuid.New()}
		s.personToken(other)
		if r := s.call(http.MethodGet, projects, other.token, nil); r.status != http.StatusForbidden {
			t.Errorf("another org reads: %s", r)
		}
	})

	t.Run("plan: a projects cap per band, refused with plan.limit_reached; idempotent creates", func(t *testing.T) {
		second := create(owner, "Gemini", "owner-2")
		if second.status != http.StatusCreated {
			t.Fatalf("create: %s", second)
		}
		if again := create(owner, "Gemini", "owner-2"); again.status != http.StatusCreated || again.str("id") != second.str("id") {
			t.Errorf("a retry makes another: %s", again)
		}
		if r := create(owner, "Mercury", "owner-2"); r.status != http.StatusConflict || r.code() != "request.idempotency_key_reused" {
			t.Errorf("a key reused for another project: %s", r)
		}
		if r := create(owner, "Mercury", "owner-3"); r.status != http.StatusCreated {
			t.Fatalf("the third: %s", r)
		}
		// Free allows three.
		r := create(owner, "Skylab", "owner-4")
		fields, _ := r.body["fields"].(map[string]any)
		if r.status != http.StatusForbidden || r.code() != "plan.limit_reached" ||
			fields["plan"] != "free" || fields["limit"] != "projects" || fields["required_plan"] != "team" {
			t.Errorf("over the cap: %s", r)
		}
		if again := create(owner, "Gemini", "owner-2"); again.status != http.StatusCreated || again.str("id") != second.str("id") {
			t.Errorf("a retry at the cap: %s", again)
		}
		// The plan is read at the moment of the action.
		if r := s.call(http.MethodPut, s.url("organization")+"/v1/organizations/"+acme.String()+"/plan", operator, map[string]any{"plan": "team"}); r.status != http.StatusOK {
			t.Fatalf("upgrade: %s", r)
		}
		if r := create(owner, "Skylab", "owner-4"); r.status != http.StatusCreated {
			t.Errorf("after the upgrade: %s", r)
		}
		shared = second.str("id")

		// The organization service runs unchanged and knows the projects
		// limit from PLANS: its plan endpoint names the cap, and its
		// downgrade checklist the tightening.
		internal := s.call(http.MethodGet, s.url("organization")+"/v1/internal/organizations/"+acme.String()+"/plan", s.serviceToken(product.Name), nil)
		if limits, _ := internal.body["limits"].(map[string]any); internal.status != http.StatusOK || limits["projects"] != float64(product.Caps["team"]) {
			t.Errorf("the organization service's plan: %s", internal)
		}
		preview := s.call(http.MethodGet, s.url("organization")+"/v1/organizations/"+acme.String()+"/plan-change?plan=free", owner.token, nil)
		if preview.status != http.StatusOK || !strings.Contains(string(preview.raw), `"code":"projects_over_cap_kept"`) {
			t.Errorf("the downgrade checklist: %s", preview)
		}
		// And what a browser reads: the catalogue, with the limit labelled
		// and capped on every band, and the org's own plan with its usage.
		catalogue := s.call(http.MethodGet, s.url("organization")+"/v1/plans", colleague.token, nil)
		if catalogue.status != http.StatusOK || !strings.Contains(string(catalogue.raw), `{"key":"projects","label":"projects"}`) {
			t.Errorf("the plan catalogue: %s", catalogue)
		}
		bands, _ := catalogue.body["bands"].([]any)
		for _, x := range bands {
			b, _ := x.(map[string]any)
			limits, _ := b["limits"].(map[string]any)
			if name, _ := b["name"].(string); b["label"] == "" || limits["projects"] != float64(product.Caps[plan.Band(name)]) {
				t.Errorf("the catalogue's %s: %v", name, b)
			}
		}
		mine := s.call(http.MethodGet, s.url("organization")+"/v1/organizations/"+acme.String()+"/plan", colleague.token, nil)
		limits, _ := mine.body["limits"].(map[string]any)
		usage, _ := mine.body["usage"].(map[string]any)
		if mine.status != http.StatusOK || mine.str("plan") != "team" || mine.str("label") != "Team" ||
			limits["projects"] != float64(product.Caps["team"]) || usage["users"] != float64(3) {
			t.Errorf("the org's plan: %s", mine)
		}
	})

	t.Run("pagination: newest first, by cursor", func(t *testing.T) {
		if r := create(owner, "Artemis", "owner-5"); r.status != http.StatusCreated {
			t.Fatalf("create: %s", r)
		}
		var seen []string
		var stamps []time.Time
		cursor := ""
		for page := 0; page < 10; page++ {
			url := projects + "?limit=2"
			if cursor != "" {
				url += "&cursor=" + cursor
			}
			r := s.call(http.MethodGet, url, colleague.token, nil)
			if r.status != http.StatusOK {
				t.Fatalf("page: %s", r)
			}
			var body struct {
				Projects []struct {
					ID        string    `json:"id"`
					CreatedAt time.Time `json:"created_at"`
				} `json:"projects"`
				NextCursor string `json:"next_cursor"`
			}
			_ = json.Unmarshal(r.raw, &body)
			if len(body.Projects) > 2 {
				t.Fatalf("a page of %d", len(body.Projects))
			}
			for _, p := range body.Projects {
				seen = append(seen, p.ID)
				stamps = append(stamps, p.CreatedAt)
			}
			if cursor = body.NextCursor; cursor == "" {
				break
			}
		}
		if len(seen) != 5 || len(slices.Compact(slices.Sorted(slices.Values(seen)))) != 5 {
			t.Errorf("paged through %v", seen)
		}
		if !slices.IsSortedFunc(stamps, func(a, b time.Time) int { return b.Compare(a) }) {
			t.Errorf("not newest first: %v", stamps)
		}
		if r := s.call(http.MethodGet, projects+"?cursor=not-a-cursor", colleague.token, nil); r.status != http.StatusBadRequest {
			t.Errorf("a made-up cursor: %s", r)
		}
	})

	t.Run("webhooks: the product's event type, sent through the template's webhooks service, beside the core's", func(t *testing.T) {
		got := make(chan webhookDelivery, 16)
		receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			got <- webhookDelivery{header: r.Header.Clone(), body: body}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer receiver.Close()

		hooks := s.url("webhooks") + "/v1/organizations/" + acme.String()
		types := s.call(http.MethodGet, hooks+"/webhook-event-types", owner.token, nil)
		if types.status != http.StatusOK || types.body["available"] != true || !strings.Contains(string(types.raw), `"type":"project.created"`) {
			t.Fatalf("event types from WEBHOOK_EVENTS: %s", types)
		}
		created := s.call(http.MethodPost, hooks+"/webhook-endpoints", owner.token,
			map[string]any{"url": receiver.URL, "event_types": []string{"project.created", "member.added"}})
		if created.status != http.StatusCreated {
			t.Fatalf("endpoint: %s", created)
		}
		secret := created.str("secret")
		// A User may not manage webhooks, and nor may this org's Admin: the
		// Owner saved the Admin's groups without it in the permissions step.
		for _, p := range []*person{colleague, admin} {
			if r := s.call(http.MethodGet, hooks+"/webhook-endpoints", p.token, nil); r.status != http.StatusForbidden {
				t.Errorf("listed endpoints without the webhooks group: %s", r)
			}
		}

		wait := func(want string) webhook.Payload {
			t.Helper()
			select {
			case d := <-got:
				if err := webhook.Verify(secret, d.header, d.body, time.Now()); err != nil {
					t.Errorf("%s: %v", want, err)
				}
				var p webhook.Payload
				_ = json.Unmarshal(d.body, &p)
				if string(p.Type) != want || p.OrgID != acme.String() || d.header.Get("webhook-id") != p.ID {
					t.Errorf("delivered %s, want %s: %s", p.Type, want, d.body)
				}
				return p
			case <-time.After(30 * time.Second):
				t.Fatalf("no %s delivery", want)
			}
			return webhook.Payload{}
		}
		// The product's own event, from the projects service.
		r := create(owner, "Webhook probe", "owner-webhooks")
		if r.status != http.StatusCreated {
			t.Fatalf("create: %s", r)
		}
		if p := wait("project.created"); p.ID != r.str("id") || p.Data["project_id"] != r.str("id") {
			t.Errorf("project.created %+v", p)
		}
		// The core's, from the audit log: a member added by the user service.
		joined := s.member(acme, "webhooks@acme.test", "user")
		p := wait("member.added")
		if p.Data["membership_id"] != joined.membership.String() || strings.Contains(fmt.Sprint(p.Data), "@") {
			t.Errorf("member.added %+v", p)
		}
		deliveries := s.call(http.MethodGet, hooks+"/webhook-deliveries", owner.token, nil)
		if deliveries.status != http.StatusOK || strings.Count(string(deliveries.raw), `"status":"succeeded"`) != 2 {
			t.Errorf("deliveries: %s", deliveries)
		}
		// The org keeps the projects the later steps count, and sends nothing
		// to a receiver that is about to close.
		if r := s.call(http.MethodDelete, hooks+"/webhook-endpoints/"+created.body["endpoint"].(map[string]any)["id"].(string), owner.token, nil); r.status != http.StatusNoContent {
			t.Errorf("delete the endpoint: %s", r)
		}
		if r := s.call(http.MethodDelete, projects+"/"+r.str("id"), owner.token, nil); r.status != http.StatusNoContent {
			t.Fatalf("delete the probe: %s", r)
		}
	})

	t.Run("audit: create, update and delete in the org's audit log", func(t *testing.T) {
		if r := s.call(http.MethodPatch, projects+"/"+shared, owner.token, map[string]any{"name": "Gemini II"}); r.status != http.StatusOK || r.str("name") != "Gemini II" {
			t.Fatalf("rename: %s", r)
		}
		doomed := create(owner, "Vostok", "owner-6")
		if doomed.status != http.StatusCreated {
			t.Fatalf("create: %s", doomed)
		}
		if r := s.call(http.MethodDelete, projects+"/"+doomed.str("id"), owner.token, nil); r.status != http.StatusNoContent {
			t.Fatalf("delete: %s", r)
		}
		if r := s.call(http.MethodGet, projects+"/"+doomed.str("id"), owner.token, nil); r.status != http.StatusNotFound || r.code() != "project.not_found" {
			t.Errorf("a deleted project: %s", r)
		}
		r := s.call(http.MethodGet, s.url("audit")+"/v1/organizations/"+acme.String()+"/audit-events?target_type=project&limit=200", owner.token, nil)
		if r.status != http.StatusOK {
			t.Fatalf("audit log: %s", r)
		}
		var log struct {
			Events []struct {
				Action   string `json:"action"`
				Actor    string `json:"actor"`
				TargetID string `json:"target_id"`
			} `json:"events"`
		}
		_ = json.Unmarshal(r.raw, &log)
		has := func(action, target, actor string) bool {
			return slices.ContainsFunc(log.Events, func(e struct {
				Action   string `json:"action"`
				Actor    string `json:"actor"`
				TargetID string `json:"target_id"`
			}) bool {
				return e.Action == action && e.TargetID == target && e.Actor == actor
			})
		}
		by := "membership:" + owner.membership.String()
		for _, want := range []struct{ action, target string }{
			{"project.created", doomed.str("id")}, {"project.updated", shared}, {"project.deleted", doomed.str("id")},
		} {
			if !has(want.action, want.target, by) {
				t.Errorf("no %s of %s by the Owner in %s", want.action, want.target, r.raw)
			}
		}
	})

	t.Run("notification and live bus: sharing tells the member", func(t *testing.T) {
		rdb := redisClient(t)
		// The live-session bus, as any listener hears it (the identity
		// service's stream to a browser is one).
		listen, cancel := context.WithCancel(ctx)
		defer cancel()
		events, err := livebus.NewBus(rdb, config.Redis{Prefix: s.prefix}.LiveEvents(), livebus.New(), nil).Subscribe(listen)
		if err != nil {
			t.Fatal(err)
		}
		member := projects + "/" + shared + "/members/" + colleague.membership.String()
		r := s.call(http.MethodPut, member, owner.token, nil)
		if r.status != http.StatusOK || r.str("membership_id") != colleague.membership.String() {
			t.Fatalf("share: %s", r)
		}
		select {
		case ev := <-events:
			if ev.Type != product.SharedEvent || ev.UserID != colleague.user.String() || ev.OrgID != acme.String() || ev.Data["project_id"] != shared {
				t.Errorf("live event %+v", ev)
			}
		case <-time.After(10 * time.Second):
			t.Error("no project.shared on the live bus")
		}

		feed := s.url("notification") + "/v1/organizations/" + acme.String() + "/notifications"
		entries := func() []map[string]any {
			r := s.call(http.MethodGet, feed, colleague.token, nil)
			var body struct {
				Notifications []map[string]any `json:"notifications"`
				Entries       []map[string]any `json:"entries"`
				Items         []map[string]any `json:"items"`
			}
			_ = json.Unmarshal(r.raw, &body)
			var out []map[string]any
			for _, e := range slices.Concat(body.Notifications, body.Entries, body.Items) {
				if e["category"] == product.Shared {
					out = append(out, e)
				}
			}
			return out
		}
		eventually(t, "the share in the colleague's feed", func() (bool, string) {
			got := entries()
			return len(got) == 1, fmt.Sprint(got)
		})
		if got := fmt.Sprint(entries()); !strings.Contains(got, "Gemini II") {
			t.Errorf("the entry does not name the project: %s", got)
		}
		// In the words of the product's copy, as the push and the email say it.
		if got := entries(); len(got) != 1 || !strings.HasSuffix(fmt.Sprint(got[0]["heading"]), "shared Gemini II with you") || got[0]["line"] != product.SharedCategory.Copy[product.Shared].Line {
			t.Errorf("the entry's words: %v", got)
		}
		// Sharing again is the same share: no second notice.
		if r := s.call(http.MethodPut, member, owner.token, nil); r.status != http.StatusOK {
			t.Errorf("share again: %s", r)
		}
		time.Sleep(500 * time.Millisecond)
		if got := entries(); len(got) != 1 {
			t.Errorf("sharing twice notified %d times", len(got))
		}
		// The category is listed for the preferences page.
		if r := s.call(http.MethodGet, s.url("notification")+"/v1/notification-categories", colleague.token, nil); !strings.Contains(string(r.raw), `"id":"project_shared"`) {
			t.Errorf("categories: %s", r)
		}
		// Only an active member of the org can be added.
		if r := s.call(http.MethodPut, projects+"/"+shared+"/members/"+uuid.NewString(), owner.token, nil); r.status != http.StatusBadRequest || r.code() != "member.not_active" {
			t.Errorf("a stranger: %s", r)
		}
		if r := s.call(http.MethodGet, projects+"/"+shared+"/members", colleague.token, nil); !strings.Contains(string(r.raw), colleague.membership.String()) {
			t.Errorf("members: %s", r)
		}
	})

	t.Run("storage: the project-cover purpose decides what is signed", func(t *testing.T) {
		cover := projects + "/" + shared + "/cover"
		if r := s.call(http.MethodPost, cover, owner.token, map[string]any{"content_type": "application/pdf", "size": 100}); r.status != http.StatusBadRequest {
			t.Errorf("a PDF: %s", r)
		}
		if r := s.call(http.MethodPost, cover, owner.token, map[string]any{"content_type": "image/png", "size": 3 << 20}); r.status != http.StatusBadRequest {
			t.Errorf("3 MB: %s", r)
		}
		coverPNG = tinyPNG(t)
		r := s.call(http.MethodPost, cover, owner.token, map[string]any{"content_type": "image/png", "size": len(coverPNG)})
		if r.status != http.StatusOK || r.str("upload_url") == "" {
			t.Fatalf("sign: %s", r)
		}
		put, _ := http.NewRequest(http.MethodPut, r.str("upload_url"), bytes.NewReader(coverPNG))
		put.Header.Set("Content-Type", "image/png")
		resp, err := http.DefaultClient.Do(put)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("upload: %d", resp.StatusCode)
		}
		got := s.call(http.MethodGet, projects+"/"+shared, colleague.token, nil)
		link := got.str("cover_url")
		if link == "" {
			t.Fatalf("no cover_url: %s", got)
		}
		resp, err = http.Get(link)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Equal(body, coverPNG) {
			t.Errorf("read back %d, %d bytes", resp.StatusCode, len(body))
		}
	})

	// A second org, on the plan with no cap, for the rate limit and for
	// offboarding.
	globex := s.org(operator, "Globex", "enterprise")
	globexOwner := s.member(globex, "owner@globex.test", "owner")
	globexAdmin := s.member(globex, "admin@globex.test", "admin")
	globexProjects := s.url(product.Name) + "/v1/organizations/" + globex.String() + "/projects"

	t.Run("rate limit: the project-create rule, per membership", func(t *testing.T) {
		for i := range 20 {
			if r := s.call(http.MethodPost, globexProjects, globexAdmin.token, map[string]any{"name": fmt.Sprintf("Batch %d", i)}, fmt.Sprintf("batch-%d", i)); r.status != http.StatusCreated {
				t.Fatalf("create %d: %s", i, r)
			}
		}
		// The rule refills one every three seconds, so on a slow machine the
		// burst above may have earned a few more; the refusal comes soon
		// after either way.
		var r reply
		for i := 20; i < 30; i++ {
			if r = s.call(http.MethodPost, globexProjects, globexAdmin.token, map[string]any{"name": fmt.Sprintf("Batch %d", i)}, fmt.Sprintf("batch-%d", i)); r.status != http.StatusCreated {
				break
			}
		}
		if r.status != http.StatusTooManyRequests || r.code() != "rate_limited" || r.header.Get("Retry-After") == "" {
			t.Errorf("past 20 in a minute: %s", r)
		}
		// Counted per membership: the Owner is not held up by it.
		if r := s.call(http.MethodPost, globexProjects, globexOwner.token, map[string]any{"name": "Owner's"}, "owner-1"); r.status != http.StatusCreated {
			t.Errorf("another member: %s", r)
		}
	})

	t.Run("data owner: in the org export and the personal export, and purged with the org", func(t *testing.T) {
		org := s.url("organization") + "/v1/organizations/"
		if r := s.call(http.MethodPost, org+acme.String()+"/exports", owner.token, nil, "export-acme"); r.status != http.StatusAccepted {
			t.Fatalf("org export: %s", r)
		}
		if r := s.call(http.MethodPost, s.url("organization")+"/v1/me/exports", colleague.token, nil, "export-colleague"); r.status != http.StatusAccepted {
			t.Fatalf("personal export: %s", r)
		}
		if r := s.call(http.MethodPost, org+globex.String()+"/close", globexOwner.token, map[string]any{"confirm_name": "Globex"}); r.status != http.StatusOK {
			t.Fatalf("close: %s", r)
		}
		// Thirty days pass: the purge is due. (The clock is the only thing
		// stood in for; the purge itself is the organization service's own.)
		asActor(t, s.dbURL, "UPDATE organization.organizations SET purge_after = now() - interval '1 minute' WHERE org_id = $1", globex)
		// Exports are made, and closing orgs purged, by the organization
		// service's own passes, which run as it starts.
		s.restart("organization")

		archive := func(list string, who *person) map[string][]byte {
			var files map[string][]byte
			eventually(t, "the export at "+list, func() (bool, string) {
				r := s.call(http.MethodGet, list, who.token, nil)
				var body struct {
					Exports []struct {
						Status      string `json:"status"`
						BlockedBy   string `json:"blocked_by"`
						DownloadURL string `json:"download_url"`
					} `json:"exports"`
				}
				_ = json.Unmarshal(r.raw, &body)
				if len(body.Exports) == 0 || body.Exports[0].DownloadURL == "" {
					return false, r.String()
				}
				files = unzip(t, body.Exports[0].DownloadURL)
				return true, ""
			})
			return files
		}

		files := archive(org+acme.String()+"/exports", owner)
		for _, o := range []string{"notification", "billing", "authorization", "identity", "user", "webhooks", "audit", product.Name} {
			if _, ok := files[o+"/data.json"]; !ok {
				t.Errorf("the org export has no %s/data.json", o)
			}
		}
		var part struct {
			Projects []struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Cover   string `json:"cover"`
				Members []struct {
					MembershipID string `json:"membership_id"`
				} `json:"members"`
			} `json:"projects"`
		}
		if err := json.Unmarshal(files[product.Name+"/data.json"], &part); err != nil || len(part.Projects) != 5 {
			t.Fatalf("the projects part: %v %s", err, files[product.Name+"/data.json"])
		}
		for _, p := range part.Projects {
			if p.ID != shared {
				continue
			}
			if p.Name != "Gemini II" || len(p.Members) != 1 || p.Members[0].MembershipID != colleague.membership.String() {
				t.Errorf("the shared project exported as %+v", p)
			}
			if got := files[product.Name+"/files/"+p.Cover]; p.Cover == "" || !bytes.Equal(got, coverPNG) {
				t.Errorf("its cover %q: %d bytes", p.Cover, len(got))
			}
		}

		mine := archive(s.url("organization")+"/v1/me/exports", colleague)
		if got := string(mine[product.Name+"/data.json"]); !strings.Contains(got, shared) || !strings.Contains(got, colleague.membership.String()) {
			t.Errorf("the personal export's projects part: %s", got)
		}

		eventually(t, "Globex purged", func() (bool, string) {
			r := s.call(http.MethodGet, org+globex.String(), operator, nil)
			return r.status == http.StatusNotFound, r.String()
		})
		if n := count(t, s.dbURL, "SELECT (SELECT count(*) FROM projects.projects WHERE org_id = $1) + (SELECT count(*) FROM projects.project_members WHERE org_id = $1)", globex); n != 0 {
			t.Errorf("%d rows of Globex left in projects", n)
		}
		if n := count(t, s.dbURL, "SELECT count(*) FROM projects.projects WHERE org_id = $1", acme); n != 5 {
			t.Errorf("Acme's projects went with Globex: %d left", n)
		}
	})

	t.Run("data owner: a member's shares erased with their account", func(t *testing.T) {
		if r := s.call(http.MethodPost, s.url("user")+"/v1/me/deletion", colleague.token, map[string]any{"confirm": "DELETE"}); r.status != http.StatusOK {
			t.Fatalf("ask to delete: %s", r)
		}
		// Fourteen days pass.
		asActor(t, s.dbURL, "UPDATE users.users SET deletion_after = now() - interval '1 minute' WHERE id = $1", colleague.user)
		// The user service's daily pass runs as it starts.
		s.restart("user")
		members := projects + "/" + shared + "/members"
		eventually(t, "the colleague forgotten", func() (bool, string) {
			r := s.call(http.MethodGet, members, owner.token, nil)
			return r.status == http.StatusOK && !strings.Contains(string(r.raw), colleague.membership.String()), r.String()
		})
		// The project stays: it is the org's.
		if r := s.call(http.MethodGet, projects+"/"+shared, owner.token, nil); r.status != http.StatusOK {
			t.Errorf("the project went with the member: %s", r)
		}
	})
}

func connect(t *testing.T, url string, as *db.Service) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	if as != nil {
		cfg.User = as.Role()
		cfg.Password, _ = dbtest.Password(*as)
	}
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// asActor runs one statement as an administrator, attributed as the
// provenance trigger requires: how the test moves a date that would
// otherwise take weeks to arrive.
func asActor(t *testing.T, url, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, url, nil)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', 'system:e2e', true)"); err != nil {
		t.Fatal(err)
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("%s: %v (%d rows)", sql, err, tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, url, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := connect(t, url, nil).QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func redisClient(t *testing.T) *redis.Client {
	t.Helper()
	opts, err := redis.ParseURL(need(t, "TEST_REDIS_URL")["TEST_REDIS_URL"])
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(opts)
	t.Cleanup(func() { c.Close() })
	return c
}

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for x := range 4 {
		img.Set(x, x, color.RGBA{R: 200, G: 40, B: 90, A: 255})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// unzip downloads an archive and reads every file in it.
func unzip(t *testing.T, url string) map[string][]byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download: %d %s", resp.StatusCode, raw)
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name], _ = io.ReadAll(r)
		r.Close()
	}
	return out
}

// webhookDelivery is one request the test's endpoint received.
type webhookDelivery struct {
	header http.Header
	body   []byte
}
