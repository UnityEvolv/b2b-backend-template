package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// SCIM groups: stored per org with their members, as the provider sends
// them. A group is a fact about who is in what; what it grants is the
// product's, through GroupSync.

var errNoGroup = &scimProblem{status: http.StatusNotFound, detail: "No such group."}

// groupResource is a group as SCIM shows it; members are left out when the
// provider asked for that, as Entra does when it only checks existence.
func (s *Server) groupResource(g store.ScimGroup, members []uuid.UUID, withMembers bool) map[string]any {
	res := map[string]any{
		"schemas": []string{schemaGroup}, "id": g.ID.String(), "displayName": g.DisplayName,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      g.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": g.LastModifiedAt.UTC().Format(time.RFC3339),
			"location":     s.scimBase(g.OrgID) + "/Groups/" + g.ID.String(),
		},
	}
	if g.ExternalID.Valid {
		res["externalId"] = g.ExternalID.String
	}
	if withMembers {
		list := make([]any, 0, len(members))
		for _, m := range members {
			list = append(list, map[string]any{"value": m.String(), "$ref": s.scimBase(g.OrgID) + "/Users/" + m.String()})
		}
		res["members"] = list
	}
	return res
}

func wantsMembers(r *http.Request) bool {
	for _, v := range strings.Split(r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "members") {
			return false
		}
	}
	return true
}

// memberIDs is the membership ids a members attribute names; anything that
// is not one is dropped.
func memberIDs(v any) []uuid.UUID {
	var out []uuid.UUID
	for _, el := range asList(v) {
		if id, err := uuid.Parse(elementValue(el)); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	p := store.ListScimGroupsParams{OrgID: org}
	if f := strings.TrimSpace(r.URL.Query().Get("filter")); f != "" {
		conds, err := parseFilter(f)
		if err != nil {
			return badRequest("invalidFilter", err.Error())
		}
		for _, c := range conds {
			v := str(c.value)
			switch c.path {
			case "displayname":
				p.DisplayName = text(&v)
			case "externalid":
				p.ExternalID = text(&v)
			case "id":
				id, err := uuid.Parse(v)
				if err != nil {
					writeSCIM(w, http.StatusOK, listResponse(nil, 0, 1))
					return nil
				}
				p.ID = pgtype.UUID{Bytes: id, Valid: true}
			default:
				return badRequest("invalidFilter", "Filtering groups on "+c.path+" is not supported; use displayName, externalId or id.")
			}
		}
	}
	start, count := scimPage(r)
	p.Skip, p.PageSize = start-1, count
	withMembers := wantsMembers(r)
	var (
		total  int64
		groups []store.ScimGroup
		all    = map[uuid.UUID][]uuid.UUID{}
	)
	err := s.cluster.Read(r.Context(), org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if total, err = q.CountScimGroups(r.Context(), store.CountScimGroupsParams{OrgID: org, ID: p.ID, DisplayName: p.DisplayName, ExternalID: p.ExternalID}); err != nil {
			return err
		}
		if groups, err = q.ListScimGroups(r.Context(), p); err != nil || !withMembers {
			return err
		}
		for _, g := range groups {
			if all[g.ID], err = q.ListScimGroupMembers(r.Context(), store.ListScimGroupMembersParams{OrgID: org, GroupID: g.ID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, s.groupResource(g, all[g.ID], withMembers))
	}
	writeSCIM(w, http.StatusOK, listResponse(out, int(total), int(start)))
	return nil
}

func (s *Server) readGroup(ctx context.Context, org uuid.UUID, rawID string) (store.ScimGroup, []uuid.UUID, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return store.ScimGroup{}, nil, errNoGroup
	}
	var (
		g       store.ScimGroup
		members []uuid.UUID
	)
	err = s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if g, err = q.GetScimGroup(ctx, store.GetScimGroupParams{OrgID: org, ID: id}); err != nil {
			return err
		}
		members, err = q.ListScimGroupMembers(ctx, store.ListScimGroupMembersParams{OrgID: org, GroupID: id})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return g, nil, errNoGroup
	}
	return g, members, err
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	g, members, err := s.readGroup(r.Context(), org, r.PathValue("id"))
	if err != nil {
		return err
	}
	writeSCIM(w, http.StatusOK, s.groupResource(g, members, wantsMembers(r)))
	return nil
}

// groupState is a group as a write leaves it.
type groupState struct {
	name, externalID string
	members          []uuid.UUID
}

// storeGroup writes a group and its whole member list.
func storeGroup(ctx context.Context, q *store.Queries, org, id uuid.UUID, st groupState, create bool) (store.ScimGroup, error) {
	if st.name == "" {
		return store.ScimGroup{}, badRequest("invalidValue", "displayName is required.")
	}
	if len(st.name) > 256 || len(st.externalID) > 256 {
		return store.ScimGroup{}, badRequest("invalidValue", "displayName and externalId are at most 256 characters.")
	}
	if _, err := q.ScimGroupClash(ctx, store.ScimGroupClashParams{OrgID: org, ID: id, ExternalID: text(&st.externalID), DisplayName: st.name}); err == nil {
		return store.ScimGroup{}, &scimProblem{status: http.StatusConflict, scimType: "uniqueness", detail: "A group with this displayName or externalId exists."}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return store.ScimGroup{}, err
	}
	var (
		g   store.ScimGroup
		err error
	)
	if create {
		g, err = q.InsertScimGroup(ctx, store.InsertScimGroupParams{OrgID: org, ID: id, ExternalID: text(&st.externalID), DisplayName: st.name})
	} else {
		g, err = q.UpdateScimGroup(ctx, store.UpdateScimGroupParams{OrgID: org, ID: id, ExternalID: text(&st.externalID), DisplayName: st.name})
	}
	if err != nil {
		return g, err
	}
	if err := q.ClearScimGroupMembers(ctx, store.ClearScimGroupMembersParams{OrgID: org, GroupID: id}); err != nil {
		return g, err
	}
	for _, m := range st.members {
		if err := q.AddScimGroupMember(ctx, store.AddScimGroupMemberParams{OrgID: org, GroupID: id, MembershipID: m}); err != nil {
			return g, err
		}
	}
	return g, nil
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	ctx := r.Context()
	res, problem := readResource(r)
	if problem != nil {
		return problem
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	st := groupState{name: str(get(res, "displayName")), externalID: str(get(res, "externalId")), members: memberIDs(get(res, "members"))}
	var (
		g       store.ScimGroup
		members []uuid.UUID
	)
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if g, err = storeGroup(ctx, q, org, id, st, true); err != nil {
			return err
		}
		members, err = q.ListScimGroupMembers(ctx, store.ListScimGroupMembersParams{OrgID: org, GroupID: id})
		return err
	})
	if err != nil {
		var p *scimProblem
		if errors.As(err, &p) {
			s.scimLog(ctx, org, "create group", nil, nil, "failed", p.detail, map[string]any{"group": st.name})
		}
		return err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "scim.group.created", TargetType: "scim_group", TargetID: id.String(),
		Details: map[string]any{"members": len(members)}}); err != nil {
		return err
	}
	s.scimLog(ctx, org, "create group", nil, &id, "ok", "", map[string]any{"group": g.DisplayName, "members": len(members)})
	if len(members) > 0 {
		if _, err := s.syncGroup(ctx, org, id, "scim"); err != nil {
			// The group is stored; what it grants catches up at the next sync.
			s.logger.Warn("group not carried to what it grants", "org_id", org, "group_id", id, "error", err)
		}
	}
	w.Header().Set("Location", s.scimBase(org)+"/Groups/"+id.String())
	writeSCIM(w, http.StatusCreated, s.groupResource(g, members, true))
	return nil
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	res, problem := readResource(r)
	if problem != nil {
		return problem
	}
	return s.scimUpdateGroup(w, r, org, "replace group", true, func(groupState) (groupState, error) {
		return groupState{name: str(get(res, "displayName")), externalID: str(get(res, "externalId")), members: memberIDs(get(res, "members"))}, nil
	})
}

// scimPatchGroup applies a PATCH through the same path parser as users, on
// the group as an object, so Entra's and Okta's member operations both land.
func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	ops, problem := readPatch(r)
	if problem != nil {
		return problem
	}
	return s.scimUpdateGroup(w, r, org, "update group", false, func(st groupState) (groupState, error) {
		list := make([]any, 0, len(st.members))
		for _, m := range st.members {
			list = append(list, map[string]any{"value": m.String()})
		}
		res := map[string]any{"displayName": st.name, "members": list}
		if st.externalID != "" {
			res["externalId"] = st.externalID
		}
		if err := applyPatch(res, ops); err != nil {
			return st, err
		}
		return groupState{name: str(get(res, "displayName")), externalID: str(get(res, "externalId")), members: memberIDs(get(res, "members"))}, nil
	})
}

// scimUpdateGroup writes a group, then carries its members to what it
// grants. A PATCH answers 204, as Entra expects; a PUT the group.
func (s *Server) scimUpdateGroup(w http.ResponseWriter, r *http.Request, org uuid.UUID, operation string, respond bool, change func(groupState) (groupState, error)) error {
	ctx := r.Context()
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return errNoGroup
	}
	var (
		g              store.ScimGroup
		before, after  []uuid.UUID
		added, removed int
	)
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		current, err := q.GetScimGroup(ctx, store.GetScimGroupParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoGroup
		}
		if err != nil {
			return err
		}
		if before, err = q.ListScimGroupMembers(ctx, store.ListScimGroupMembersParams{OrgID: org, GroupID: id}); err != nil {
			return err
		}
		st, err := change(groupState{name: current.DisplayName, externalID: current.ExternalID.String, members: before})
		if err != nil {
			return err
		}
		if g, err = storeGroup(ctx, q, org, id, st, false); err != nil {
			return err
		}
		after, err = q.ListScimGroupMembers(ctx, store.ListScimGroupMembersParams{OrgID: org, GroupID: id})
		return err
	})
	if err != nil {
		var p *scimProblem
		if errors.As(err, &p) && p.status != http.StatusNotFound {
			s.scimLog(ctx, org, operation, nil, &id, "failed", p.detail, nil)
		}
		return err
	}
	was := map[uuid.UUID]bool{}
	for _, m := range before {
		was[m] = true
	}
	for _, m := range after {
		if !was[m] {
			added++
		}
		delete(was, m)
	}
	removed = len(was)
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "scim.group.updated", TargetType: "scim_group", TargetID: id.String(),
		Details: map[string]any{"added": added, "removed": removed}}); err != nil {
		return err
	}
	s.scimLog(ctx, org, operation, nil, &id, "ok", "", map[string]any{"group": g.DisplayName, "added": added, "removed": removed})
	if added > 0 || removed > 0 {
		if _, err := s.syncGroup(ctx, org, id, "scim"); err != nil {
			// The group is stored; what it grants catches up at the next sync.
			s.logger.Warn("group not carried to what it grants", "org_id", org, "group_id", id, "error", err)
		}
	}
	if !respond {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	writeSCIM(w, http.StatusOK, s.groupResource(g, after, true))
	return nil
}

// scimDeleteGroup empties the group first, so its members lose what it
// granted, and removes it once that is done. If emptying it would take
// too many people out at once, the sync halts and the group stays, empty,
// until an admin decides.
func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	ctx := r.Context()
	g, _, err := s.readGroup(ctx, org, r.PathValue("id"))
	if err != nil {
		return err
	}
	if err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		return store.New(tx).ClearScimGroupMembers(ctx, store.ClearScimGroupMembersParams{OrgID: org, GroupID: g.ID})
	}); err != nil {
		return err
	}
	halted, err := s.syncGroup(ctx, org, g.ID, "delete")
	if err != nil {
		return err
	}
	if !halted {
		if err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
			_, err := store.New(tx).DeleteScimGroup(ctx, store.DeleteScimGroupParams{OrgID: org, ID: g.ID})
			return err
		}); err != nil {
			return err
		}
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "scim.group.deleted", TargetType: "scim_group", TargetID: g.ID.String(),
		Details: map[string]any{"halted": halted}}); err != nil {
		return err
	}
	s.scimLog(ctx, org, "delete group", nil, &g.ID, "ok", "", map[string]any{"group": g.DisplayName})
	w.WriteHeader(http.StatusNoContent)
	return nil
}
