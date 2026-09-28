package server

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLanding(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	m := func(org uuid.UUID, status string, last *time.Time) membership {
		return membership{OrgID: org, MembershipID: uuid.New(), Status: status, LastActiveAt: last}
	}

	// The org that authenticated them, when active there.
	if got, ok := landing([]membership{m(a, "active", nil), m(b, "active", ago(time.Hour))}, a, now); !ok || got == nil || got.OrgID != a {
		t.Errorf("signed-in org: %v %v", got, ok)
	}
	// One membership: straight in, even when they authenticated elsewhere.
	if got, ok := landing([]membership{m(a, "active", nil)}, c, now); !ok || got == nil || got.OrgID != a {
		t.Errorf("one membership: %v %v", got, ok)
	}
	// Several: the one used last, when recent.
	if got, ok := landing([]membership{m(a, "active", ago(48*time.Hour)), m(b, "active", ago(time.Hour))}, c, now); !ok || got == nil || got.OrgID != b {
		t.Errorf("most recent: %v %v", got, ok)
	}
	// Several, none recent: the chooser.
	if got, ok := landing([]membership{m(a, "active", ago(60*24*time.Hour)), m(b, "active", nil)}, c, now); !ok || got != nil {
		t.Errorf("none recent: %v %v", got, ok)
	}
	// Deactivated is skipped; refused when it is the only one.
	if got, ok := landing([]membership{m(a, "deactivated", ago(time.Hour)), m(b, "active", nil)}, a, now); !ok || got == nil || got.OrgID != b {
		t.Errorf("skip deactivated: %v %v", got, ok)
	}
	if _, ok := landing([]membership{m(a, "suspended", nil)}, a, now); ok {
		t.Error("suspended only was not refused")
	}
	if _, ok := landing(nil, a, now); ok {
		t.Error("no memberships was not refused")
	}
}
