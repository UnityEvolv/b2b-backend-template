package webhook_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
)

// The Standard Webhooks (and Svix) published vector: a receiver using any
// library that follows the specification verifies what this package signs.
const (
	vectorSecret    = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	vectorID        = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	vectorTimestamp = 1614265330
	vectorBody      = `{"test": 2432232314}`
	vectorSignature = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
)

func TestSignatureVector(t *testing.T) {
	key, err := webhook.ParseSecret(vectorSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got := webhook.Signature(key, vectorID, vectorTimestamp, []byte(vectorBody)); got != vectorSignature {
		t.Fatalf("signature %s, want %s", got, vectorSignature)
	}
	h := http.Header{}
	webhook.Sign(h, vectorID, time.Unix(vectorTimestamp, 0), []byte(vectorBody), key)
	if h.Get("webhook-signature") != vectorSignature || h.Get("webhook-id") != vectorID || h.Get("webhook-timestamp") != "1614265330" {
		t.Fatalf("headers %v", h)
	}
	if err := webhook.Verify(vectorSecret, h, []byte(vectorBody), time.Unix(vectorTimestamp+60, 0)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	key, secret, err := webhook.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret %q", secret)
	}
	now := time.Now()
	body := []byte(`{"id":"x"}`)
	h := http.Header{}
	webhook.Sign(h, "msg_1", now, body, key)
	if err := webhook.Verify(secret, h, []byte(`{"id":"y"}`), now); !errors.Is(err, webhook.ErrSignature) {
		t.Errorf("changed body: %v", err)
	}
	if err := webhook.Verify(secret, h, body, now.Add(10*time.Minute)); !errors.Is(err, webhook.ErrTimestamp) {
		t.Errorf("replayed later: %v", err)
	}
	other := h.Clone()
	other.Set("webhook-id", "msg_2")
	if err := webhook.Verify(secret, other, body, now); !errors.Is(err, webhook.ErrSignature) {
		t.Errorf("another id: %v", err)
	}
	if err := webhook.Verify(secret, http.Header{}, body, now); !errors.Is(err, webhook.ErrNoSignature) {
		t.Errorf("no headers: %v", err)
	}
}

// During a rotation a delivery carries a signature under each secret, so a
// receiver still on the old one and one already on the new both verify.
func TestTwoSecretsTwoSignatures(t *testing.T) {
	newKey, newSecret, _ := webhook.NewSecret()
	oldKey, oldSecret, _ := webhook.NewSecret()
	now := time.Now()
	body := []byte(`{}`)
	h := http.Header{}
	webhook.Sign(h, "msg_1", now, body, newKey, oldKey)
	if n := len(strings.Fields(h.Get("webhook-signature"))); n != 2 {
		t.Fatalf("%d signatures, want 2", n)
	}
	for _, s := range []string{newSecret, oldSecret} {
		if err := webhook.Verify(s, h, body, now); err != nil {
			t.Errorf("verify: %v", err)
		}
	}
	_, stranger, _ := webhook.NewSecret()
	if err := webhook.Verify(stranger, h, body, now); err == nil {
		t.Error("a third secret verified")
	}
}

func TestRegistry(t *testing.T) {
	r := webhook.New()
	for _, ty := range []webhook.Type{webhook.MemberAdded, webhook.MemberRemoved, webhook.MemberRoleChanged} {
		if !r.Known(ty) {
			t.Errorf("%s not registered", ty)
		}
	}
	if err := r.Load(`[{"type":"project.created","description":"A project was created."}]`); err != nil {
		t.Fatal(err)
	}
	if !r.Known("project.created") || len(r.Types()) != 4 {
		t.Fatalf("types %v", r.Types())
	}
	for _, bad := range []string{`[{"type":"Project"}]`, `[{"type":"webhook.test"}]`, `[{"type":"a.b","extra":1}]`, `{`} {
		if err := r.Load(bad); err == nil {
			t.Errorf("%s loaded", bad)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("a bad type registered")
		}
	}()
	r.Register(webhook.EventType{Type: "nodot"})
}

func TestCheckDataRefusesPersonalData(t *testing.T) {
	ok := map[string]any{"membership_id": "0192", "tags": []any{"a", "b"}, "nested": map[string]any{"count": 2}}
	if err := webhook.CheckData(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{"email": "x"},
		{"user": map[string]any{"Name": "Ada"}},
		{"note": "write to ada@example.com"},
		{"list": []any{"ok", "bob@example.org"}},
		{"blob": strings.Repeat("a", webhook.MaxData)},
	} {
		if err := webhook.CheckData(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestFromAudit(t *testing.T) {
	cases := []struct {
		entry webhook.AuditEntry
		want  webhook.Type
		ok    bool
	}{
		{webhook.AuditEntry{Action: "membership.created", TargetID: "m1", Details: map[string]any{"user_id": "u1", "role": "user", "email": "x@y.z"}}, webhook.MemberAdded, true},
		{webhook.AuditEntry{Action: "membership.status_changed", TargetID: "m1", Details: map[string]any{"from": "active", "to": "deactivated"}}, webhook.MemberRemoved, true},
		{webhook.AuditEntry{Action: "membership.status_changed", TargetID: "m1", Details: map[string]any{"from": "deactivated", "to": "active"}}, webhook.MemberAdded, true},
		{webhook.AuditEntry{Action: "membership.status_changed", TargetID: "m1", Details: map[string]any{"from": "deactivated", "to": "suspended"}}, "", false},
		{webhook.AuditEntry{Action: "membership.left", TargetID: "m1"}, webhook.MemberRemoved, true},
		{webhook.AuditEntry{Action: "role.changed", TargetID: "m1", Details: map[string]any{"from": "user", "to": "admin"}}, webhook.MemberRoleChanged, true},
		{webhook.AuditEntry{Action: "session.signed_in", TargetID: "s1"}, "", false},
	}
	for _, c := range cases {
		ty, data, ok := webhook.FromAudit(c.entry)
		if ok != c.ok || ty != c.want {
			t.Errorf("%s %v: %s %v", c.entry.Action, c.entry.Details, ty, ok)
			continue
		}
		if ok {
			if data["membership_id"] != "m1" {
				t.Errorf("%s: data %v", c.entry.Action, data)
			}
			if err := webhook.CheckData(data); err != nil {
				t.Errorf("%s: %v", c.entry.Action, err)
			}
		}
	}
}

func TestClientEmits(t *testing.T) {
	var got webhook.Message
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got.Type == "nope.nope" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"webhooks.unknown_type","message":"no"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c := webhook.NewClient(srv.URL, auth.StaticToken("t"), nil)
	if err := c.Emit(context.Background(), "org1", webhook.Message{Type: "project.created", Data: map[string]any{"project_id": "p"}}); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/internal/organizations/org1/events" || got.Data["project_id"] != "p" {
		t.Fatalf("%s %v", path, got)
	}
	if err := c.Emit(context.Background(), "org1", webhook.Message{Type: "nope.nope"}); !errors.Is(err, webhook.ErrRefused) {
		t.Fatalf("refusal: %v", err)
	}
}
