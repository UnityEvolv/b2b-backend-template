package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/store"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
)

// The data endpoints of a data owner (pkg/orgdata): an org's projects in its
// export and its purge, a person's shares in their own export, and a
// member's shares forgotten when their account is deleted. The first three
// are the organization service's alone, the last the user service's too.

func onlyOrganization(ctx context.Context) bool {
	return auth.RequireService(ctx, orgdata.Caller) == nil
}

var notOrganization = api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}

type exportedMember struct {
	MembershipID uuid.UUID `json:"membership_id"`
	AddedBy      string    `json:"added_by"`
	AddedAt      time.Time `json:"added_at"`
}

type exportedProject struct {
	ID             uuid.UUID        `json:"id"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Cover          string           `json:"cover,omitempty"`
	CreatedBy      string           `json:"created_by"`
	CreatedAt      time.Time        `json:"created_at"`
	LastModifiedBy string           `json:"last_modified_by"`
	LastModifiedAt time.Time        `json:"last_modified_at"`
	Members        []exportedMember `json:"members"`
}

// coverName is where a cover goes in the archive, under this service's
// files/ folder.
func coverName(p store.Project) string {
	ext := map[string]string{"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}[p.CoverContentType.String]
	return "covers/" + p.ID.String() + ext
}

// dataPart is v, with files, as the contract's DataPart.
func dataPart(v any, files []orgdata.File) (api.DataPart, error) {
	p, err := orgdata.Marshal(product.Name, v, files)
	if err != nil {
		return api.DataPart{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return api.DataPart{}, err
	}
	var out api.DataPart
	err = json.Unmarshal(raw, &out)
	return out, err
}

// ExportOrgData is every project with its members, and every cover as a
// file.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: notOrganization}, nil
	}
	var (
		projects []store.Project
		members  []store.ProjectMember
	)
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if projects, err = q.ExportProjects(ctx, req.OrgId); err != nil {
			return err
		}
		members, err = q.ExportMembers(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	byProject := map[uuid.UUID][]exportedMember{}
	for _, m := range members {
		byProject[m.ProjectID] = append(byProject[m.ProjectID], exportedMember{MembershipID: m.MembershipID, AddedBy: m.CreatedBy, AddedAt: m.CreatedAt})
	}
	out := make([]exportedProject, 0, len(projects))
	files := []orgdata.File{}
	for _, p := range projects {
		e := exportedProject{ID: p.ID, Name: p.Name, Description: p.Description, CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt,
			LastModifiedBy: p.LastModifiedBy, LastModifiedAt: p.LastModifiedAt, Members: byProject[p.ID]}
		if e.Members == nil {
			e.Members = []exportedMember{}
		}
		if p.CoverKey.Valid {
			e.Cover = coverName(p)
			files = append(files, orgdata.File{Key: p.CoverKey.String, Name: e.Cover})
		}
		out = append(out, e)
	}
	part, err := dataPart(map[string]any{"projects": out}, files)
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(part), nil
}

// PurgeOrgData deletes every project of the org, members with them, and
// counts what is left. The covers go with the org's files, which the
// organization service deletes after every owner has answered.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: notOrganization}, nil
	}
	var remaining int32
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.PurgeProjects(ctx, req.OrgId); err != nil {
			return err
		}
		var err error
		remaining, err = q.CountOrgRows(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.PurgeOrgData200JSONResponse{Remaining: int(remaining)}, nil
}

// ExportUserData is the projects each of the person's memberships is a
// member of.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportUserData403JSONResponse(notOrganization), nil
	}
	var values []string
	if req.Params.Membership != nil {
		values = *req.Params.Membership
	}
	memberships, err := orgdata.ParseMemberships(values)
	if err != nil {
		return api.ExportUserData400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(invalid("A membership is not valid.", map[string]string{"membership": "org_id:membership_id"}))}, nil
	}
	type shared struct {
		ProjectID uuid.UUID `json:"project_id"`
		Name      string    `json:"name"`
		AddedAt   time.Time `json:"added_at"`
	}
	type orgShares struct {
		OrgID        uuid.UUID `json:"org_id"`
		MembershipID uuid.UUID `json:"membership_id"`
		Projects     []shared  `json:"projects"`
	}
	out := []orgShares{}
	for _, m := range memberships {
		var rows []store.ProjectsOfMembershipRow
		err := s.cluster.Read(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			var err error
			rows, err = store.New(tx).ProjectsOfMembership(ctx, store.ProjectsOfMembershipParams{OrgID: m.OrgID, MembershipID: m.MembershipID})
			return err
		})
		if err != nil {
			return nil, err
		}
		o := orgShares{OrgID: m.OrgID, MembershipID: m.MembershipID, Projects: []shared{}}
		for _, r := range rows {
			o.Projects = append(o.Projects, shared{ProjectID: r.ID, Name: r.Name, AddedAt: r.AddedAt})
		}
		out = append(out, o)
	}
	part, err := dataPart(map[string]any{"organizations": out}, nil)
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(part), nil
}

// ForgetMembershipData drops the member from every project, for account
// deletion. The projects they made stay: they are the org's, and name the
// member only by id.
func (s *Server) ForgetMembershipData(ctx context.Context, req api.ForgetMembershipDataRequestObject) (api.ForgetMembershipDataResponseObject, error) {
	if auth.RequireService(ctx, orgdata.Caller, orgdata.Eraser) != nil {
		return api.ForgetMembershipData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization and user services only."}}, nil
	}
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).ForgetMembership(ctx, store.ForgetMembershipParams{OrgID: req.OrgId, MembershipID: req.MembershipId})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.ForgetMembershipData204Response{}, nil
}
