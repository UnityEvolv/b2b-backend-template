package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// Group sync and reconciliation (UO-181). SCIM pushes are lost, duplicated
// and reordered by every provider eventually, so what a group grants is
// always sent to the office service whole, and a daily pass puts right what
// drifted, in the provider's direction. A change that would take too much
// of the org away at once is halted for an admin instead of applied.

// GroupMember is one person a group grants an office to.
type GroupMember struct {
	MembershipID uuid.UUID `json:"membership_id"`
	UserID       uuid.UUID `json:"user_id"`
}

// GroupSyncResult is what a group sync changed, or would.
type GroupSyncResult struct {
	Added   []uuid.UUID `json:"added"`
	Removed []uuid.UUID `json:"removed"`
}

// ErrNoOffice means the office is not in the org.
var ErrNoOffice = errors.New("no such office")

// Offices is what this service needs of the office service: who a group
// grants an office to.
type Offices interface {
	SyncGroup(ctx context.Context, org, office, group uuid.UUID, members []GroupMember, dryRun bool) (GroupSyncResult, error)
}

// WithOffices is s, carrying groups to the offices they feed.
func (s *Server) WithOffices(o Offices) *Server {
	s.offices = o
	return s
}

// Notice is an event for the notification service.
type Notice struct {
	ID       string         `json:"id"`
	OrgID    string         `json:"org_id"`
	Kind     string         `json:"kind"`
	Category string         `json:"category"`
	Audience string         `json:"audience"`
	Link     string         `json:"link"`
	Data     map[string]any `json:"data"`
}

// Notifier hands notices to the notification service.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// RedisNotifier publishes on the notification service's channel.
type RedisNotifier struct{ Client *redis.Client }

// Notify publishes n.
func (r RedisNotifier) Notify(ctx context.Context, n Notice) error {
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return r.Client.Publish(ctx, "unityofis:notify", raw).Err()
}

// WithNotifier is s, telling admins what SCIM needs them for.
func (s *Server) WithNotifier(n Notifier) *Server {
	s.notices = n
	return s
}

// WithHaltAt sets the share of the org's active members a single change
// may take away before it halts; 0 is the default quarter.
func (s *Server) WithHaltAt(fraction float64) *Server {
	s.haltFraction = fraction
	return s
}

func (s *Server) notifyAdmins(ctx context.Context, org uuid.UUID, id, kind string, data map[string]any) {
	if s.notices == nil {
		return
	}
	if err := s.notices.Notify(ctx, Notice{ID: "scim:" + id, OrgID: org.String(), Kind: kind, Category: "admin_directory", Audience: "admins", Link: "/scim", Data: data}); err != nil {
		s.logger.Warn("scim notice not sent", "org_id", org, "error", err)
	}
}

// haltAbove is how many people one change may take away before it halts:
// a quarter of the active members, and never fewer than five.
func (s *Server) haltAbove(active int) int {
	fraction := s.haltFraction
	if fraction <= 0 {
		fraction = 0.25
	}
	return max(5, int(float64(active)*fraction))
}

// haltedChange is one change waiting for an admin.
type haltedChange struct {
	// group: a group's offices would lose these people. deactivate: the
	// reconciliation would deactivate them.
	Kind        string      `json:"kind"`
	GroupID     *uuid.UUID  `json:"group_id,omitempty"`
	GroupName   string      `json:"group_name,omitempty"`
	OfficeIDs   []uuid.UUID `json:"office_ids,omitempty"`
	Memberships []uuid.UUID `json:"memberships"`
	// The provider deleted the group; applying removes it.
	DeleteGroup bool `json:"delete_group,omitempty"`
}

func (c haltedChange) same(o haltedChange) bool {
	if c.Kind != o.Kind {
		return false
	}
	return c.GroupID == nil || (o.GroupID != nil && *c.GroupID == *o.GroupID)
}

func decodeHalted(raw []byte) []haltedChange {
	var out []haltedChange
	_ = json.Unmarshal(raw, &out)
	return out
}

// halt holds change for an admin, replacing an earlier hold of the same
// thing, and tells the admins.
func (s *Server) halt(ctx context.Context, org uuid.UUID, change haltedChange, reason string) error {
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var changes []haltedChange
		if st, err := q.GetScimState(ctx, org); err == nil {
			for _, c := range decodeHalted(st.HaltedChanges) {
				if !c.same(change) {
					changes = append(changes, c)
				}
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		raw, err := json.Marshal(append(changes, change))
		if err != nil {
			return err
		}
		return q.HaltScim(ctx, store.HaltScimParams{OrgID: org, Reason: text(&reason), Changes: raw})
	})
	if err != nil {
		return err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "scim.sync.halted", TargetType: "organization", TargetID: org.String(),
		Details: map[string]any{"kind": change.Kind, "people": len(change.Memberships)}}); err != nil {
		return err
	}
	s.scimLog(ctx, org, "halt", nil, change.GroupID, "halted", reason, map[string]any{"kind": change.Kind, "people": len(change.Memberships)})
	s.notifyAdmins(ctx, org, "halt:"+time.Now().UTC().Format(time.RFC3339), "scim_halted", map[string]any{
		"message": reason, "people": len(change.Memberships), "heading": "A directory sync was halted", "line": reason,
	})
	return nil
}

// syncGroup carries a group's members to every office it feeds. It halts
// instead when the offices would lose more people at once than haltAbove
// allows: an emptied group is the classic SCIM accident.
func (s *Server) syncGroup(ctx context.Context, org, group uuid.UUID, cause string) (bool, error) {
	if s.offices == nil {
		return false, nil
	}
	ctx = db.WithActor(ctx, scimActor)
	var (
		g       store.ScimGroup
		offices []uuid.UUID
		members []GroupMember
		active  int64
	)
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if g, err = q.GetScimGroup(ctx, store.GetScimGroupParams{OrgID: org, ID: group}); err != nil {
			return err
		}
		mapped, err := q.ListOfficesOfGroup(ctx, store.ListOfficesOfGroupParams{OrgID: org, GroupID: group})
		if err != nil {
			return err
		}
		for _, m := range mapped {
			if !m.Paused {
				offices = append(offices, m.OfficeID)
			}
		}
		rows, err := q.GroupMembersForSync(ctx, store.GroupMembersForSyncParams{OrgID: org, GroupID: group})
		if err != nil {
			return err
		}
		for _, r := range rows {
			members = append(members, GroupMember{MembershipID: r.ID, UserID: r.UserID})
		}
		active, err = q.CountActiveMemberships(ctx, org)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(offices) == 0) {
		return false, err
	}
	if err != nil {
		return false, err
	}
	losing := map[uuid.UUID]bool{}
	for _, office := range offices {
		res, err := s.offices.SyncGroup(ctx, org, office, group, members, true)
		if errors.Is(err, ErrNoOffice) {
			continue
		}
		if err != nil {
			return false, err
		}
		for _, m := range res.Removed {
			losing[m] = true
		}
	}
	if len(losing) > s.haltAbove(int(active)) {
		who := make([]uuid.UUID, 0, len(losing))
		for m := range losing {
			who = append(who, m)
		}
		reason := fmt.Sprintf("Syncing the group %q would take %d people out of its offices at once, more than this organization allows in one change.", g.DisplayName, len(who))
		return true, s.halt(ctx, org, haltedChange{Kind: "group", GroupID: &group, GroupName: g.DisplayName, OfficeIDs: offices, Memberships: who, DeleteGroup: cause == "delete"}, reason)
	}
	return false, s.carry(ctx, org, g, offices, members, cause)
}

// carry sends a group's members to its offices, unguarded.
func (s *Server) carry(ctx context.Context, org uuid.UUID, g store.ScimGroup, offices []uuid.UUID, members []GroupMember, cause string) error {
	added, removed := 0, 0
	for _, office := range offices {
		res, err := s.offices.SyncGroup(ctx, org, office, g.ID, members, false)
		if errors.Is(err, ErrNoOffice) {
			continue
		}
		if err != nil {
			return err
		}
		added, removed = added+len(res.Added), removed+len(res.Removed)
	}
	if added > 0 || removed > 0 {
		s.scimLog(ctx, org, "sync group offices", nil, &g.ID, "ok", "", map[string]any{"group": g.DisplayName, "offices": len(offices), "added": added, "removed": removed, "by": cause})
	}
	return nil
}

// groupMembers is who a group grants its offices to now.
func (s *Server) groupMembers(ctx context.Context, org, group uuid.UUID) (store.ScimGroup, []GroupMember, error) {
	var (
		g       store.ScimGroup
		members []GroupMember
	)
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if g, err = q.GetScimGroup(ctx, store.GetScimGroupParams{OrgID: org, ID: group}); err != nil {
			return err
		}
		rows, err := q.GroupMembersForSync(ctx, store.GroupMembersForSyncParams{OrgID: org, GroupID: group})
		for _, r := range rows {
			members = append(members, GroupMember{MembershipID: r.ID, UserID: r.UserID})
		}
		return err
	})
	return g, members, err
}

// RunReconciliation is the daily pass over every org that uses SCIM. There
// is no scheduler; a correction can be a day late.
func (s *Server) RunReconciliation(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if err := s.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("scim reconciliation failed", "error", err)
		}
	}
}

// ReconcileAll is one pass.
func (s *Server) ReconcileAll(ctx context.Context) error {
	ctx = db.WithActor(ctx, scimActor)
	var orgs []uuid.UUID
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrgsUsingScim(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, org := range orgs {
		band, err := s.plans.Band(ctx, org.String())
		if err != nil || plan.CheckFeature(band, plan.SCIM) != nil {
			continue
		}
		if err := s.Reconcile(ctx, org); err != nil {
			s.logger.Warn("scim reconciliation not finished", "org_id", org, "error", err)
		}
	}
	return nil
}

// Reconcile puts one org right against the provider's last word: status
// toward what it said about active, and every mapped group's offices toward
// its members. Office memberships added by hand, profiles and roles above
// User are never touched. Every correction is audited.
func (s *Server) Reconcile(ctx context.Context, org uuid.UUID) error {
	ctx = db.WithActor(ctx, scimActor)
	var (
		drift  []store.ScimDriftRow
		mapped []store.ScimGroupOffice
		active int64
	)
	if err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if drift, err = q.ScimDrift(ctx, org); err != nil {
			return err
		}
		if mapped, err = q.ListGroupOffices(ctx, org); err != nil {
			return err
		}
		active, err = q.CountActiveMemberships(ctx, org)
		return err
	}); err != nil {
		return err
	}
	var off, on []uuid.UUID
	for _, d := range drift {
		if d.Membership.ScimActive.Bool {
			on = append(on, d.Membership.ID)
		} else {
			off = append(off, d.Membership.ID)
		}
	}
	if len(off) > s.haltAbove(int(active)) {
		reason := fmt.Sprintf("The daily reconciliation would deactivate %d people at once, more than this organization allows in one change.", len(off))
		if err := s.halt(ctx, org, haltedChange{Kind: "deactivate", Memberships: off}, reason); err != nil {
			return err
		}
		off = nil
	}
	for _, id := range append(off, on...) {
		if err := s.reconcileOne(ctx, org, id); err != nil {
			return err
		}
	}
	seen := map[uuid.UUID]bool{}
	for _, m := range mapped {
		if m.Paused || seen[m.GroupID] {
			continue
		}
		seen[m.GroupID] = true
		if _, err := s.syncGroup(ctx, org, m.GroupID, "reconciliation"); err != nil {
			return err
		}
	}
	return s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		return store.New(tx).PruneScimLog(ctx, org)
	})
}

// reconcileOne moves one person's status to what the provider last said,
// if it still differs.
func (s *Server) reconcileOne(ctx context.Context, org, id uuid.UUID) error {
	var (
		m       store.Membership
		moved   *statusChange
		refusal *plan.Refusal
	)
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		row, err := q.ScimMembership(ctx, store.ScimMembershipParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil || !row.Membership.ScimActive.Valid {
			return err
		}
		m, moved, refusal, err = s.setActive(ctx, q, row.Membership, row.Membership.ScimActive.Bool)
		if refusal != nil {
			return errRefusedByPlan
		}
		return err
	})
	var p *scimProblem
	switch {
	case errors.Is(err, errRefusedByPlan):
		s.scimLog(ctx, org, "reconcile", &id, nil, "failed", refusal.Message, map[string]any{"reason": "user_cap"})
		return nil
	case errors.As(err, &p):
		s.scimLog(ctx, org, "reconcile", &id, nil, "failed", p.detail, nil)
		return nil
	case err != nil:
		return err
	case moved == nil:
		return nil
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "scim.reconciled", TargetType: "membership", TargetID: id.String(),
		Details: map[string]any{"differed": "status", "from": moved.from, "to": moved.to}}); err != nil {
		return err
	}
	if err := s.afterStatus(ctx, m, moved, "reconciliation"); err != nil {
		return err
	}
	s.scimLog(ctx, org, "reconcile", &id, nil, "ok", "", map[string]any{"from": moved.from, "to": moved.to})
	return nil
}

// applyHalted carries out what was halted, as it stands now.
func (s *Server) applyHalted(ctx context.Context, org uuid.UUID, changes []haltedChange) error {
	for _, c := range changes {
		switch c.Kind {
		case "group":
			if c.GroupID == nil || s.offices == nil {
				continue
			}
			g, members, err := s.groupMembers(ctx, org, *c.GroupID)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if err := s.carry(ctx, org, g, c.OfficeIDs, members, "admin"); err != nil {
				return err
			}
			if c.DeleteGroup && len(members) == 0 {
				if err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
					_, err := store.New(tx).DeleteScimGroup(ctx, store.DeleteScimGroupParams{OrgID: org, ID: g.ID})
					return err
				}); err != nil {
					return err
				}
			}
		case "deactivate":
			for _, id := range c.Memberships {
				if err := s.reconcileOne(ctx, org, id); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// dismissHalted leaves things as they are: a group's offices stop following
// it until the mapping is saved again, and the provider's word on the
// people it would have deactivated is forgotten until it speaks again.
func (s *Server) dismissHalted(ctx context.Context, org uuid.UUID, changes []haltedChange) error {
	return s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, c := range changes {
			switch c.Kind {
			case "group":
				if c.GroupID == nil {
					continue
				}
				for _, office := range c.OfficeIDs {
					if err := q.PauseGroupOffice(ctx, store.PauseGroupOfficeParams{OrgID: org, GroupID: *c.GroupID, OfficeID: office}); err != nil {
						return err
					}
				}
			case "deactivate":
				for _, id := range c.Memberships {
					if err := q.ClearScimActive(ctx, store.ClearScimActiveParams{OrgID: org, ID: id}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}
