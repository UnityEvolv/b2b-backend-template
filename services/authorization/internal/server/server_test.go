package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/server"
)

var (
	acme   = uuid.MustParse("01922b5e-0000-7000-8000-0000000000a1")
	globex = uuid.MustParse("01922b5e-0000-7000-8000-0000000000b2")
)

// fakeMemberships is the user service in memory: roles by "org/membership".
type fakeMemberships struct {
	mu    sync.Mutex
	rows  map[string]server.MembershipInfo
	calls []string
}

func (f *fakeMemberships) key(org, m uuid.UUID) string { return org.String() + "/" + m.String() }

func (f *fakeMemberships) add(org uuid.UUID, role authz.Role, status string) uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.New()
	f.rows[f.key(org, id)] = server.MembershipInfo{ID: id, OrgID: org, Role: role, Status: status, Kind: "member", Email: id.String()[:8] + "@example.com"}
	return id
}

func (f *fakeMemberships) Get(_ context.Context, org, m uuid.UUID) (server.MembershipInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[f.key(org, m)]
	if !ok {
		return server.MembershipInfo{}, server.ErrNotFound
	}
	return row, nil
}

func (f *fakeMemberships) SetRole(_ context.Context, org, m uuid.UUID, role authz.Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[f.key(org, m)]
	if !ok {
		return server.ErrNotFound
	}
	if row.Role == authz.Owner {
		owners := 0
		for _, r := range f.rows {
			if r.OrgID == org && r.Role == authz.Owner && r.Status == "active" {
				owners++
			}
		}
		if owners <= 1 {
			return server.ErrLastOwner
		}
	}
	row.Role = role
	f.rows[f.key(org, m)] = row
	f.calls = append(f.calls, "role:"+string(role))
	return nil
}

type memoryRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memoryRecorder) Record(_ context.Context, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

type fixture struct {
	t        *testing.T
	h        http.Handler
	issuer   *stubissuer.Issuer
	people   *fakeMemberships
	recorder *memoryRecorder
	mail     *memoryMail
	pool     *pgxpool.Pool
}

// count is how many times an action was audited.
func (m *memoryRecorder) count(action string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, ev := range m.events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

func (m *memoryRecorder) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.events))
	for _, ev := range m.events {
		out = append(out, ev.Action)
	}
	return out
}

func newAPI(t *testing.T, groups ...*authz.Registry) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("authorization")
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrator, err := db.Migrator(stdlib.OpenDBFromPool(pool), service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, err := stubissuer.New("test", "b2bapp")
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewStaticVerifier("test", "b2bapp", issuer.PublicKeys())
	people := &fakeMemberships{rows: map[string]server.MembershipInfo{}}
	recorder := &memoryRecorder{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := http.NewServeMux()
	httpx.Health(root)
	mail := &memoryMail{}
	srv := server.New(db.SingleShard(pool), logger, recorder, people, server.Transfer{Email: mail, Orgs: orgNames{}, Apps: map[string]string{"admin": "http://admin.test"}})
	if len(groups) > 0 {
		srv.WithGroups(groups[0])
	}
	root.Handle("/", auth.Require(verifier, srv.Handler(httpx.NewMux())))
	return &fixture{t: t, h: httpx.Logged(logger, root), issuer: issuer, people: people, recorder: recorder, mail: mail, pool: pool}
}

// as is a token for a membership in org.
func (f *fixture) as(org, membership uuid.UUID) string {
	raw, err := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org.String(), MembershipID: membership.String()}, time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) service(name string) string {
	raw, err := f.issuer.Issue(auth.Caller{Service: name}, time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) do(method, path, token string, body any) (int, map[string]any) {
	f.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Body.Len() == 0 {
		return rec.Code, nil
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("%s %s: body is not JSON: %q", method, path, rec.Body.String())
	}
	return rec.Code, out
}

func has(list any, want string) bool {
	items, _ := list.([]any)
	for _, i := range items {
		if i == want {
			return true
		}
	}
	return false
}

// End to end: a User is refused an Admin action, an
// Admin cannot modify another Admin, an Owner grants billing to Admin and it
// takes effect, the last Owner cannot be demoted, and an Admin in one org
// has no admin rights in another.
func TestRolesAndPermissions(t *testing.T) {
	f := newAPI(t)
	owner := f.people.add(acme, authz.Owner, "active")
	admin := f.people.add(acme, authz.Admin, "active")
	admin2 := f.people.add(acme, authz.Admin, "active")
	user := f.people.add(acme, authz.User, "active")
	// The same admin person is a plain User at globex.
	elsewhere := f.people.add(globex, authz.User, "active")
	perms := "/v1/organizations/" + acme.String() + "/permissions"
	grant := func(org, m uuid.UUID) map[string]any {
		status, out := f.do(http.MethodGet, "/v1/internal/organizations/"+org.String()+"/memberships/"+m.String()+"/permissions", f.service("user"), nil)
		if status != http.StatusOK {
			t.Fatalf("grant: %d %v", status, out)
		}
		return out
	}

	// Defaults: Admin has users, audit and sso; no billing; no Owner-only action.
	g := grant(acme, admin)
	if !has(g["permissions"], "users") || has(g["permissions"], "billing") || has(g["permissions"], "assign_roles") {
		t.Errorf("admin default grant: %v", g)
	}
	// A User has nothing to do with admin actions; a service reading the grant sees so.
	if g := grant(acme, user); len(g["permissions"].([]any)) != 0 {
		t.Errorf("user grant: %v", g)
	}
	// A User is refused an Admin action here too: configuring is Owner only, assigning roles is Owner only.
	if status, _ := f.do(http.MethodPut, perms, f.as(acme, user), map[string]any{"admin": []string{"users"}, "billing_admin": []string{"billing"}}); status != http.StatusForbidden {
		t.Errorf("user configuring: %d", status)
	}
	// An Admin cannot modify another Admin: assigning roles is not theirs at all.
	if status, _ := f.do(http.MethodPut, "/v1/organizations/"+acme.String()+"/memberships/"+admin2.String()+"/role", f.as(acme, admin), map[string]any{"role": "user"}); status != http.StatusForbidden {
		t.Errorf("admin re-roling an admin: %d", status)
	}
	// An Owner grants billing to the Admin role and it takes effect on the next check.
	status, out := f.do(http.MethodPut, perms, f.as(acme, owner), map[string]any{"admin": []string{"users", "audit", "sso", "api_keys", "billing"}, "billing_admin": []string{"billing"}})
	if status != http.StatusOK || !has(out["admin"], "billing") || len(out["warnings"].([]any)) != 0 {
		t.Fatalf("grant billing: %d %v", status, out)
	}
	if g := grant(acme, admin); !has(g["permissions"], "billing") {
		t.Errorf("billing not in effect: %v", g)
	}
	// Owner-only actions cannot be configured onto a role.
	if status, _ := f.do(http.MethodPut, perms, f.as(acme, owner), map[string]any{"admin": []string{"assign_roles"}, "billing_admin": []string{}}); status != http.StatusBadRequest {
		t.Errorf("owner-only action configured: %d", status)
	}
	// Leaving nobody but the Owner able to do something warns.
	_, out = f.do(http.MethodPut, perms, f.as(acme, owner), map[string]any{"admin": []string{"users"}, "billing_admin": []string{}})
	if len(out["warnings"].([]any)) != 4 {
		t.Errorf("warnings: %v", out["warnings"])
	}
	// Every member may read the configuration; another org's member may not.
	if status, _ := f.do(http.MethodGet, perms, f.as(acme, user), nil); status != http.StatusOK {
		t.Errorf("member reading config: %d", status)
	}
	if status, _ := f.do(http.MethodGet, perms, f.as(globex, elsewhere), nil); status != http.StatusForbidden {
		t.Errorf("stranger reading config: %d", status)
	}
	// An Admin in one org has no admin rights in another: the globex membership is a User.
	if g := grant(globex, elsewhere); len(g["permissions"].([]any)) != 0 {
		t.Errorf("admin rights leaked across orgs: %v", g)
	}

	// The Owner re-roles an Admin to a User, audited; cannot make an Owner; cannot demote themself.
	rolePath := func(m uuid.UUID) string {
		return "/v1/organizations/" + acme.String() + "/memberships/" + m.String() + "/role"
	}
	if status, out := f.do(http.MethodPut, rolePath(admin2), f.as(acme, owner), map[string]any{"role": "user"}); status != http.StatusOK || out["role"] != "user" {
		t.Errorf("owner re-roling: %d %v", status, out)
	}
	if status, _ := f.do(http.MethodPut, rolePath(user), f.as(acme, owner), map[string]any{"role": "owner"}); status != http.StatusBadRequest {
		t.Errorf("assigning owner: %d", status)
	}
	if status, out := f.do(http.MethodPut, rolePath(owner), f.as(acme, owner), map[string]any{"role": "admin"}); status != http.StatusConflict || out["code"] != "role.self" {
		t.Errorf("owner demoting themself: %d %v", status, out)
	}
	// The last Owner cannot be demoted, even by a platform operator.
	operator, _ := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: auth.PlatformOrg, MembershipID: uuid.NewString()}, time.Hour)
	if status, out := f.do(http.MethodPut, rolePath(owner), operator, map[string]any{"role": "admin"}); status != http.StatusConflict || out["code"] != "membership.last_owner" {
		t.Errorf("last owner demoted: %d %v", status, out)
	}
	// A deactivated membership has no permissions, whatever its role.
	gone := f.people.add(acme, authz.Admin, "deactivated")
	if g := grant(acme, gone); len(g["permissions"].([]any)) != 0 {
		t.Errorf("deactivated admin still has permissions: %v", g)
	}
	// Unknown membership; a person asking the internal endpoint.
	if status, _ := f.do(http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/memberships/"+uuid.NewString()+"/permissions", f.service("user"), nil); status != http.StatusNotFound {
		t.Errorf("unknown membership: %d", status)
	}
	if status, _ := f.do(http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/memberships/"+admin.String()+"/permissions", f.as(acme, owner), nil); status != http.StatusForbidden {
		t.Errorf("a person reading grants: %d", status)
	}

	actions := map[string]int{}
	for _, ev := range f.recorder.events {
		actions[ev.Action]++
	}
	if actions["permissions.changed"] != 2 || actions["role.changed"] != 1 {
		t.Errorf("audit: %v", actions)
	}
}

// memoryMail is the notification outbox, kept in memory.
type memoryMail struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *memoryMail) Send(_ context.Context, msg email.Message) (email.Queued, error) {
	if err := msg.Validate(); err != nil {
		return email.Queued{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return email.Queued{ID: uuid.NewString(), State: "queued"}, nil
}

// orgNames is the organization service: every org is called by its id's
// first eight characters.
type orgNames struct{}

func (orgNames) Name(_ context.Context, orgID uuid.UUID) (string, error) {
	return "Org " + orgID.String()[:8], nil
}
