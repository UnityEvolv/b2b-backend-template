package server_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
)

type emitted struct {
	org string
	msg webhook.Message
}

type emitter struct {
	mu   sync.Mutex
	sent []emitted
	fail bool
}

func (e *emitter) all() []emitted {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]emitted(nil), e.sent...)
}

func (e *emitter) failing() {
	e.mu.Lock()
	e.fail = true
	e.mu.Unlock()
}

func (e *emitter) Emit(_ context.Context, org string, m webhook.Message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail {
		return errors.New("webhooks service down")
	}
	e.sent = append(e.sent, emitted{org, m})
	return nil
}

// The core's webhook events come from the audit log: a membership entry,
// once written, is forwarded as its event, with the entry's id as the
// message id and ids only in its data. Anything else is not, nor is the
// platform org's. A webhooks service that is down never fails the entry.
func TestMembershipEntriesAreForwardedAsWebhookEvents(t *testing.T) {
	e := &emitter{}
	f := newFixture(t, e)
	rec := f.recorder(t, "user")
	admin := f.member(t, orgA)
	ctx := asRequest(admin)
	membership := uuid.NewString()
	if err := rec.Record(ctx, audit.Event{OrgID: orgA, Action: "membership.created", TargetType: "membership", TargetID: membership,
		Details: map[string]any{"user_id": uuid.NewString(), "role": "user", "kind": "member", "source": "invite"}}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(ctx, audit.Event{OrgID: orgA, Action: "session.signed_in", TargetType: "session", TargetID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(ctx, audit.Event{OrgID: auth.PlatformOrg, Action: "membership.created", TargetType: "membership", TargetID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	sent := e.all()
	if len(sent) != 1 {
		t.Fatalf("forwarded %d, want 1: %+v", len(sent), sent)
	}
	got := sent[0]
	if got.org != orgA || got.msg.Type != webhook.MemberAdded || got.msg.Data["membership_id"] != membership || got.msg.Data["role"] != "user" {
		t.Errorf("forwarded %+v", got)
	}
	if _, err := uuid.Parse(got.msg.ID); err != nil || got.msg.OccurredAt.IsZero() {
		t.Errorf("message id %q, occurred %v", got.msg.ID, got.msg.OccurredAt)
	}
	if err := webhook.CheckData(got.msg.Data); err != nil {
		t.Errorf("data: %v", err)
	}
	status, page := f.list(t, orgA, f.token(t, admin), "?action=membership.")
	if status != 200 || page["events"].([]any)[0].(map[string]any)["id"] != got.msg.ID {
		t.Errorf("the message id is not the entry's: %v", page)
	}

	e.failing()
	if err := rec.Record(ctx, audit.Event{OrgID: orgA, Action: "role.changed", TargetType: "membership", TargetID: membership,
		Details: map[string]any{"from": "user", "to": "admin"}}); err != nil {
		t.Errorf("a webhooks failure failed the entry: %v", err)
	}
}
