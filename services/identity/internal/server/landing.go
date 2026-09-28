package server

import (
	"time"

	"github.com/google/uuid"
)

// membership is what the landing rule needs to know about one org.
type membership struct {
	OrgID        uuid.UUID
	MembershipID uuid.UUID
	Status       string
	LastActiveAt *time.Time
}

// recentEnough is how long ago "the org they were last active in" still
// counts. Past it, a person with several orgs is asked.
const recentEnough = 30 * 24 * time.Hour

// landing is which membership a sign-in lands in, or nil for the chooser.
//
// The provider that authenticated the person is the org resolved first: if
// their membership there is active, that is where they land. Otherwise one
// active membership goes straight in; several go to the one used most
// recently, if recently enough; and several with none recent go to the
// chooser. Deactivated and suspended memberships are skipped, and refused
// (nil, false) when there is nothing else.
func landing(all []membership, signedInOrg uuid.UUID, now time.Time) (*membership, bool) {
	var active []membership
	for _, m := range all {
		if m.Status == "active" {
			active = append(active, m)
		}
	}
	if len(active) == 0 {
		return nil, false
	}
	for i := range active {
		if active[i].OrgID == signedInOrg {
			return &active[i], true
		}
	}
	if len(active) == 1 {
		return &active[0], true
	}
	var best *membership
	for i := range active {
		m := &active[i]
		if m.LastActiveAt == nil || now.Sub(*m.LastActiveAt) > recentEnough {
			continue
		}
		if best == nil || m.LastActiveAt.After(*best.LastActiveAt) {
			best = m
		}
	}
	if best != nil {
		return best, true
	}
	return nil, true
}
