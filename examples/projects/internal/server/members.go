package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/store"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
)

const codeNotActive = "member.not_active"

func toMember(m store.ProjectMember) api.ProjectMember {
	return api.ProjectMember{ProjectId: m.ProjectID, MembershipId: m.MembershipID, AddedBy: m.CreatedBy, AddedAt: m.CreatedAt}
}

// ListProjectMembers is who a project is shared with.
func (s *Server) ListProjectMembers(ctx context.Context, req api.ListProjectMembersRequestObject) (api.ListProjectMembersResponseObject, error) {
	if r := mayRead(ctx, req.OrgId); r != nil {
		if r.status == http.StatusUnauthorized {
			return api.ListProjectMembers401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(r.body)}, nil
		}
		return api.ListProjectMembers403JSONResponse(r.body), nil
	}
	out := api.ProjectMemberList{Members: []api.ProjectMember{}}
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		rows, err := q.ListMembers(ctx, store.ListMembersParams{OrgID: req.OrgId, ProjectID: req.ProjectId})
		for _, m := range rows {
			out.Members = append(out.Members, toMember(m))
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ListProjectMembers404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	return api.ListProjectMembers200JSONResponse(out), nil
}

// AddProjectMember shares a project with an active member of the org. The
// first time, the member is told and their open sessions hear of it.
func (s *Server) AddProjectMember(ctx context.Context, req api.AddProjectMemberRequestObject) (api.AddProjectMemberResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.AddProjectMember401JSONResponse(r.body), nil
		}
		return api.AddProjectMember403JSONResponse(r.body), nil
	}
	var project store.Project
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		project, err = store.New(tx).GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.AddProjectMember404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	// Who it is, from the user service, asked now with this service's token.
	member, err := s.deps.Members.Get(ctx, req.OrgId, req.MembershipId)
	if errors.Is(err, ErrNoMember) || (err == nil && member.Status != "active") {
		return api.AddProjectMember400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: codeNotActive,
			Message: "Only an active member of the organization can be added.", Fields: &map[string]string{"membership_id": "an active membership in this organization"}}}, nil
	}
	if err != nil {
		return nil, err
	}
	var (
		row   store.ProjectMember
		added bool
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		key := store.AddMemberParams{OrgID: req.OrgId, ProjectID: req.ProjectId, MembershipID: req.MembershipId}
		var err error
		row, err = q.AddMember(ctx, key)
		if errors.Is(err, pgx.ErrNoRows) {
			row, err = q.GetMember(ctx, store.GetMemberParams(key))
			return err
		}
		if err != nil {
			return err
		}
		added = true
		return s.record(ctx, req.OrgId, req.ProjectId, "project.member_added", map[string]any{"membership_id": req.MembershipId.String()})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// The project went in between.
		return api.AddProjectMember404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	if added {
		s.shared(ctx, project, member, row)
	}
	return api.AddProjectMember200JSONResponse(toMember(row)), nil
}

// shared tells the member, through the notification service, and pushes
// the event to their open sessions. Both best effort: the share stands, and
// the project is in their list the next time they look.
func (s *Server) shared(ctx context.Context, p store.Project, member Member, row store.ProjectMember) {
	var actor *uuid.UUID
	if c, ok := auth.CallerFrom(ctx); ok {
		if id, err := uuid.Parse(c.MembershipID); err == nil {
			actor = &id
		}
	}
	if s.deps.Notifier != nil {
		err := s.deps.Notifier.Notify(ctx, Notice{
			ID:    fmt.Sprintf("projects:shared:%s:%s:%d", p.ID, member.ID, row.CreatedAt.UnixNano()),
			OrgID: p.OrgID, Kind: product.Shared, Category: product.Shared,
			Recipients: []uuid.UUID{member.ID}, Actor: actor,
			Link: "/projects/" + p.ID.String(), Group: "project:" + p.ID.String(),
			Data: map[string]any{"project": p.Name, "project_id": p.ID.String()},
		})
		if err != nil {
			s.logger.Warn("share not notified", "org_id", p.OrgID, "project_id", p.ID, "error", err)
		}
	}
	if s.deps.Live != nil {
		err := s.deps.Live.Publish(ctx, livebus.Event{Type: product.SharedEvent, OrgID: p.OrgID.String(), UserID: member.UserID.String(),
			MembershipID: member.ID.String(), Data: map[string]any{"project_id": p.ID.String()}})
		if err != nil {
			s.logger.Warn("share not pushed", "org_id", p.OrgID, "project_id", p.ID, "error", err)
		}
	}
}

// RemoveProjectMember stops sharing a project with a member.
func (s *Server) RemoveProjectMember(ctx context.Context, req api.RemoveProjectMemberRequestObject) (api.RemoveProjectMemberResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.RemoveProjectMember401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(r.body)}, nil
		}
		return api.RemoveProjectMember403JSONResponse(r.body), nil
	}
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		n, err := q.RemoveMember(ctx, store.RemoveMemberParams{OrgID: req.OrgId, ProjectID: req.ProjectId, MembershipID: req.MembershipId})
		if err != nil || n == 0 {
			return err
		}
		return s.record(ctx, req.OrgId, req.ProjectId, "project.member_removed", map[string]any{"membership_id": req.MembershipId.String()})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RemoveProjectMember404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	return api.RemoveProjectMember204Response{}, nil
}
