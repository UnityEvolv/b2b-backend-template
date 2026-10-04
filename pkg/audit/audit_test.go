package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

const org = "01922b5e-0000-7000-8000-0000000000a1"

// The context a handler has: the caller from auth, the request info from the
// logging middleware.
func requestContext(c auth.Caller) context.Context {
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	req.Header.Set("X-Request-Id", "req-42")
	var ctx context.Context
	httpx.Logged(slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	return auth.WithCaller(ctx, c)
}

func TestRecordSendsWhatTheContextKnows(t *testing.T) {
	var got map[string]any
	var authz, requestID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz, requestID = r.Header.Get("Authorization"), r.Header.Get("X-Request-Id")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := audit.NewClient(srv.URL, auth.StaticToken("svc-token"), srv.Client())
	ctx := requestContext(auth.Caller{UserID: "u", OrgID: org, MembershipID: "01922b5e-0000-7000-8000-0000000000c1"})
	err := c.Record(ctx, audit.Event{OrgID: org, Action: "member.role.changed", TargetType: "membership", TargetID: "m1", Details: map[string]any{"role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if authz != "Bearer svc-token" || requestID != "req-42" {
		t.Errorf("headers: %q %q", authz, requestID)
	}
	if got["actor"] != "membership:01922b5e-0000-7000-8000-0000000000c1" || got["source_ip"] != "198.51.100.9" || got["request_id"] != "req-42" || got["org_id"] != org {
		t.Errorf("body: %v", got)
	}
	if got["details"].(map[string]any)["role"] != "admin" {
		t.Errorf("details: %v", got["details"])
	}
}

func TestRecordFailsRatherThanDrops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusForbidden, httpx.CodeForbidden, "no")
	}))
	defer srv.Close()
	c := audit.NewClient(srv.URL, auth.StaticToken("t"), srv.Client())
	ctx := db.WithActor(context.Background(), db.SystemActor("organization"))
	err := c.Record(ctx, audit.Event{OrgID: org, Action: "a.b", TargetType: "t", TargetID: "1"})
	if !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("refused entry: %v", err)
	}

	down := audit.NewClient("http://127.0.0.1:1", auth.StaticToken("t"), nil)
	if err := down.Record(ctx, audit.Event{OrgID: org, Action: "a.b", TargetType: "t", TargetID: "1"}); !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("unreachable service: %v", err)
	}
}

func TestRecordNeedsAnActorAndAWellFormedEvent(t *testing.T) {
	c := audit.NewClient("http://unused", auth.StaticToken("t"), nil)
	if err := c.Record(context.Background(), audit.Event{OrgID: org, Action: "a.b", TargetType: "t", TargetID: "1"}); err == nil {
		t.Fatal("no actor anywhere, yet recorded")
	}
	ctx := db.WithActor(context.Background(), db.SystemActor("organization"))
	for _, bad := range []audit.Event{
		{Action: "a.b", TargetType: "t", TargetID: "1"},
		{OrgID: org, Action: "Changed", TargetType: "t", TargetID: "1"},
		{OrgID: org, Action: "a.b", TargetID: "1"},
	} {
		if err := c.Record(ctx, bad); err == nil {
			t.Errorf("%+v was sent", bad)
		}
	}
}

type keep struct{ events []audit.Event }

func (k *keep) Record(_ context.Context, ev audit.Event) error {
	k.events = append(k.events, ev)
	return nil
}

func TestAnImpersonatedRequestIsTheOperatorsInTheOrgsLog(t *testing.T) {
	const (
		operator = "01922b5e-0000-7000-8000-0000000000e1"
		run      = "01922b5e-0000-7000-8000-0000000000e2"
		grant    = "01922b5e-0000-7000-8000-0000000000e3"
		member   = "01922b5e-0000-7000-8000-0000000000c1"
	)
	k := &keep{}
	c := auth.Caller{UserID: "01922b5e-0000-7000-8000-0000000000c2", OrgID: org, MembershipID: member,
		ImpersonatorID: operator, ImpersonationID: run, ImpersonationGrantID: grant}
	err := audit.Impersonation(k, "user").RecordImpersonated(requestContext(c), auth.ImpersonatedRequest{Caller: c, Method: http.MethodPost, Path: "/v1/me", Refused: true})
	if err != nil {
		t.Fatal(err)
	}
	ev := k.events[0]
	if ev.OrgID != org || ev.Action != audit.ActionImpersonatedRequest || ev.TargetType != "impersonation" || ev.TargetID != run || ev.Actor != db.UserActor(operator) {
		t.Fatalf("event: %+v", ev)
	}
	d := ev.Details
	if d["service"] != "user" || d["method"] != "POST" || d["path"] != "/v1/me" || d["grant_id"] != grant || d["membership_id"] != member || d["refused"] != true {
		t.Fatalf("details: %v", d)
	}
}
