package server_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
)

// memoryLive is the live-session bus.
type memoryLive struct {
	mu     sync.Mutex
	events []livebus.Event
}

func (m *memoryLive) Publish(_ context.Context, ev livebus.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

// A role change is pushed as membership.changed, so the person's
// open apps read their grant again; setting the same role pushes nothing.
func TestARoleChangeIsPushedLive(t *testing.T) {
	f := newAPI(t)
	live := &memoryLive{}
	f.srv.WithLive(live)
	m := f.signIn(t, acme, "uma@example.com", "Uma", nil)
	path := "/v1/internal/organizations/" + acme.String() + "/memberships/" + id(t, m, "membership", "id") + "/role"
	for _, role := range []string{"admin", "admin"} {
		if status, out := f.do(t, http.MethodPut, path, f.service(t, "authorization"), map[string]any{"role": role}); status != http.StatusOK {
			t.Fatalf("role: %d %v", status, out)
		}
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	if len(live.events) != 1 {
		t.Fatalf("pushed %+v", live.events)
	}
	ev := live.events[0]
	if ev.Type != livebus.MembershipChanged || ev.OrgID != acme.String() || ev.UserID != id(t, m, "user", "id") ||
		ev.MembershipID != id(t, m, "membership", "id") || ev.Code != "role_changed" || ev.Data["role"] != "admin" {
		t.Errorf("pushed %+v", ev)
	}
}
