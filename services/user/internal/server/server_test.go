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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/server"
)

// Two orgs on known plans, and one nobody has heard of.
var (
	acme    = uuid.MustParse("01922b5e-0000-7000-8000-0000000000a1")
	globex  = uuid.MustParse("01922b5e-0000-7000-8000-0000000000b2")
	unknown = uuid.MustParse("01922b5e-0000-7000-8000-0000000000ff")
	// initech is on Enterprise, for SCIM.
	initech = uuid.MustParse("01922b5e-0000-7000-8000-0000000000c3")
)

// memoryRecorder keeps every audit event, so a test can say what was recorded.
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

func (m *memoryRecorder) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.events))
	for _, ev := range m.events {
		out = append(out, ev.Action)
	}
	return out
}

// plans knows the two orgs; anyone else does not exist.
type plans struct{}

func (plans) Band(_ context.Context, orgID string) (plan.Band, error) {
	switch orgID {
	case acme.String():
		return plan.Free, nil
	case globex.String():
		return plan.Team50, nil
	case initech.String():
		return plan.Enterprise, nil
	}
	return "", plan.ErrNoOrganization
}

type fixture struct {
	h        http.Handler
	issuer   *stubissuer.Issuer
	recorder *memoryRecorder
	grants   authz.Static
	sessions *memorySessions
	srv      *server.Server
	groups   *fakeGroupSync
	notices  *memoryNotices
}

// memorySessions is the identity service, remembering which memberships it
// was told had ended.
type memorySessions struct {
	mu      sync.Mutex
	ended   []string // "membership:reason"
	invites []server.NewInvite
	deleted []uuid.UUID       // people the identity service was told to delete
	refuse  map[string]string // email => code the identity service answers with
}

func (m *memorySessions) CreateInvite(_ context.Context, in server.NewInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if code := m.refuse[in.Email]; code != "" {
		return &server.InviteRefusal{Status: 409, Code: code}
	}
	m.invites = append(m.invites, in)
	return nil
}

func (m *memorySessions) MembershipEnded(_ context.Context, _ uuid.UUID, membershipID, _ uuid.UUID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ended = append(m.ended, membershipID.String()+":"+reason)
	return nil
}

// The whole path, end to end, against a real Postgres.
func newAPI(t *testing.T) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("user")

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

	migrator, err := db.Migrator(stdlib.OpenDBFromPool(pool), service, migrations.FS)
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
	recorder := &memoryRecorder{}
	sessions := &memorySessions{}
	// Who may do what, by "org/membership"; a test adds an Owner or an Admin.
	grants := authz.Static{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := http.NewServeMux()
	httpx.Health(root)
	// Photos need a bucket: the store at TEST_S3_ENDPOINT; without one the
	// photo tests skip.
	var uploads *storage.Client
	if endpoint := os.Getenv("TEST_S3_ENDPOINT"); endpoint != "" {
		var err error
		uploads, err = storage.New(storage.Config{Endpoint: endpoint, Region: "us-east-1", Bucket: os.Getenv("TEST_S3_BUCKET"), AccessKey: os.Getenv("TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("TEST_S3_SECRET_KEY"), PathStyle: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	groups, notices := newFakeGroupSync(), &memoryNotices{}
	srv := server.New(db.SingleShard(pool), logger, recorder, plans{}, grants, sessions, sessions, uploads).
		WithGroupSync(groups).WithNotifier(notices)
	root.Handle("/scim/", srv.SCIM(nil))
	root.Handle("/", auth.Require(verifier, srv.Handler(httpx.NewMux())))
	return &fixture{h: httpx.Logged(logger, root), issuer: issuer, recorder: recorder, grants: grants, sessions: sessions,
		srv: srv, groups: groups, notices: notices}
}

func (f *fixture) service(t *testing.T, name string) string {
	t.Helper()
	raw, err := f.issuer.Issue(auth.Caller{Service: name}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) person(t *testing.T, userID, orgID, membershipID string) string {
	t.Helper()
	raw, err := f.issuer.Issue(auth.Caller{UserID: userID, OrgID: orgID, MembershipID: membershipID}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) platform(t *testing.T) string {
	return f.person(t, uuid.NewString(), auth.PlatformOrg, uuid.NewString())
}

func (f *fixture) do(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", uuid.NewString())
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNoContent {
		return rec.Code, nil
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: body is not JSON: %q", method, path, rec.Body.String())
	}
	return rec.Code, out
}

// signIn is a person authenticating through org's identity provider.
func (f *fixture) signIn(t *testing.T, org uuid.UUID, email, name string, directory map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"org_id": org, "email": email, "name": name, "idp_subject": "sub-" + email}
	if directory != nil {
		body["directory"] = directory
	}
	status, out := f.do(t, http.MethodPost, "/v1/internal/sign-ins", f.service(t, "identity"), body)
	if status != http.StatusOK {
		t.Fatalf("sign-in %s to %s: %d %v", email, org, status, out)
	}
	return out
}

func id(t *testing.T, m map[string]any, keys ...string) string {
	t.Helper()
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("no %v in %v", keys, m)
		}
		v = mm[k]
	}
	s, _ := v.(string)
	return s
}

// DeleteUser remembers who the identity service was told to delete.
func (m *memorySessions) DeleteUser(_ context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, userID)
	return nil
}
