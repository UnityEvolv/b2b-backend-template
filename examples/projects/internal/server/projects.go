package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/store"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
)

const (
	codeKeyReused = "request.idempotency_key_reused"
	// coverLink is how long a cover's signed read link lasts.
	coverLink = time.Hour
	// uploadWindow is how long the browser has to upload a cover.
	uploadWindow = 10 * time.Minute
)

// toAPI is a project as the API shows it, with a fresh link to its cover.
func (s *Server) toAPI(ctx context.Context, p store.Project, members int64) api.Project {
	out := api.Project{
		Id: p.ID, OrgId: p.OrgID, Name: p.Name, Description: p.Description, MemberCount: int(members),
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt, LastModifiedBy: p.LastModifiedBy, LastModifiedAt: p.LastModifiedAt,
	}
	if p.CoverKey.Valid && s.deps.Files != nil {
		if key, err := storage.ParseKey(p.CoverKey.String); err == nil {
			if link, err := s.deps.Files.ReadURL(ctx, p.OrgID.String(), key, coverLink); err == nil {
				u := link.String()
				out.CoverUrl = &u
			}
		}
	}
	return out
}

// one is a project with its member count, as the API shows it.
func (s *Server) one(ctx context.Context, q *store.Queries, p store.Project) (api.Project, error) {
	n, err := q.CountMembers(ctx, store.CountMembersParams{OrgID: p.OrgID, ProjectID: p.ID})
	if err != nil {
		return api.Project{}, err
	}
	return s.toAPI(ctx, p, n), nil
}

func (s *Server) record(ctx context.Context, org, project uuid.UUID, action string, details map[string]any) error {
	return s.deps.Audit.Record(ctx, audit.Event{OrgID: org.String(), Action: action, TargetType: "project", TargetID: project.String(), Details: details})
}

func checkName(name string, fields map[string]string) string {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 200 {
		fields["name"] = "1 to 200 characters"
	}
	return name
}

func checkDescription(d string, fields map[string]string) string {
	d = strings.TrimSpace(d)
	if utf8.RuneCountInString(d) > 2000 {
		fields["description"] = "at most 2000 characters"
	}
	return d
}

// ListProjects is one page of the org's projects, newest first.
func (s *Server) ListProjects(ctx context.Context, req api.ListProjectsRequestObject) (api.ListProjectsResponseObject, error) {
	if r := mayRead(ctx, req.OrgId); r != nil {
		if r.status == http.StatusUnauthorized {
			return api.ListProjects401JSONResponse(r.body), nil
		}
		return api.ListProjects403JSONResponse(r.body), nil
	}
	cursor, after, err := httpx.DecodeCursor(deref(req.Params.Cursor))
	if err != nil {
		return api.ListProjects400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(invalid("The cursor is not valid.", map[string]string{"cursor": "a next_cursor from a previous page"}))}, nil
	}
	size := httpx.PageSize(req.Params.Limit, 50, 100)
	page := api.ProjectPage{Projects: []api.Project{}}
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		rows, err := q.ListProjects(ctx, store.ListProjectsParams{OrgID: req.OrgId, After: after, CursorAt: cursor.At, CursorID: cursor.ID, PageSize: int32(size + 1)})
		if err != nil {
			return err
		}
		if len(rows) > size {
			rows = rows[:size]
			last := rows[size-1]
			next := httpx.Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
			page.NextCursor = &next
		}
		ids := make([]uuid.UUID, len(rows))
		for i, p := range rows {
			ids[i] = p.ID
		}
		counts, err := q.MemberCounts(ctx, store.MemberCountsParams{OrgID: req.OrgId, ProjectIds: ids})
		if err != nil {
			return err
		}
		members := map[uuid.UUID]int64{}
		for _, c := range counts {
			members[c.ProjectID] = c.Members
		}
		for _, p := range rows {
			page.Projects = append(page.Projects, s.toAPI(ctx, p, members[p.ID]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return api.ListProjects200JSONResponse(page), nil
}

// CreateProject makes a project, within the org's plan.
//
// The idempotency key is the client's: a retry with the same key finds the
// project the first request made and answers with it, even at the cap. The
// cap is read from the plan now, and creates in one org queue on a lock, so
// two at the cap cannot both pass the count.
func (s *Server) CreateProject(ctx context.Context, req api.CreateProjectRequestObject) (api.CreateProjectResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.CreateProject401JSONResponse(r.body), nil
		}
		return api.CreateProject403JSONResponse(r.body), nil
	}
	fields := map[string]string{}
	name := checkName(req.Body.Name, fields)
	description := checkDescription(deref(req.Body.Description), fields)
	key := strings.TrimSpace(req.Params.IdempotencyKey)
	if key == "" || len(key) > 200 {
		fields["Idempotency-Key"] = "1 to 200 characters"
	}
	if len(fields) > 0 {
		return api.CreateProject400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(invalid("Some fields are not valid.", fields))}, nil
	}
	ent, err := s.deps.Plans.Entitlements(ctx, req.OrgId.String())
	if err != nil {
		return nil, err
	}
	actor, _ := db.ActorFrom(ctx)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var (
		out     api.Project
		refused api.CreateProjectResponseObject
		created bool
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if err := q.LockOrgProjects(ctx, req.OrgId.String()); err != nil {
			return err
		}
		byKey := store.ProjectByIdempotencyKeyParams{OrgID: req.OrgId, CreatedBy: string(actor), IdempotencyKey: pgtype.Text{String: key, Valid: true}}
		if p, err := q.ProjectByIdempotencyKey(ctx, byKey); err == nil {
			if p.Name != name || p.Description != description {
				refused = api.CreateProject409JSONResponse{Code: codeKeyReused, Message: "This idempotency key was already used for a different request."}
				return nil
			}
			out, err = s.one(ctx, q, p)
			return err
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		n, err := q.CountProjects(ctx, req.OrgId)
		if err != nil {
			return err
		}
		if err := ent.CheckLimit(product.Projects, int(n)); err != nil {
			rf, ok := plan.AsRefusal(err)
			if !ok {
				return err
			}
			fields := rf.Fields()
			refused = api.CreateProject403JSONResponse{Code: plan.Code, Message: rf.Message, Fields: &fields}
			return nil
		}
		p, err := q.InsertProject(ctx, store.InsertProjectParams{OrgID: req.OrgId, ID: id, Name: name, Description: description, IdempotencyKey: byKey.IdempotencyKey})
		if err != nil {
			return err
		}
		// In the transaction: an entry that cannot be recorded undoes the
		// create rather than dropping the record.
		if err := s.record(ctx, req.OrgId, p.ID, "project.created", map[string]any{"plan": string(ent.Band)}); err != nil {
			return err
		}
		out = s.toAPI(ctx, p, 0)
		created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if refused != nil {
		return refused, nil
	}
	if created {
		// To the org's webhook endpoints, after the commit: the project's
		// id is the message id, so a retried send is one event. Ids only.
		if err := s.deps.Webhooks.Emit(ctx, req.OrgId.String(), webhook.Message{ID: id.String(), Type: product.CreatedEvent,
			Data: map[string]any{"project_id": id.String(), "created_by": string(actor)}}); err != nil {
			s.logger.Warn("webhook event not sent", "org_id", req.OrgId.String(), "project_id", id.String(), "error", err)
		}
	}
	return api.CreateProject201JSONResponse(out), nil
}

// GetProject is one project.
func (s *Server) GetProject(ctx context.Context, req api.GetProjectRequestObject) (api.GetProjectResponseObject, error) {
	if r := mayRead(ctx, req.OrgId); r != nil {
		if r.status == http.StatusUnauthorized {
			return api.GetProject401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(r.body)}, nil
		}
		return api.GetProject403JSONResponse(r.body), nil
	}
	var out api.Project
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		p, err := q.GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId})
		if err != nil {
			return err
		}
		out, err = s.one(ctx, q, p)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetProject404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetProject200JSONResponse(out), nil
}

// UpdateProject renames a project or changes its description.
func (s *Server) UpdateProject(ctx context.Context, req api.UpdateProjectRequestObject) (api.UpdateProjectResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.UpdateProject401JSONResponse(r.body), nil
		}
		return api.UpdateProject403JSONResponse(r.body), nil
	}
	fields := map[string]string{}
	params := store.UpdateProjectParams{OrgID: req.OrgId, ID: req.ProjectId}
	var changed []string
	if req.Body.Name != nil {
		params.Name = pgtype.Text{String: checkName(*req.Body.Name, fields), Valid: true}
		changed = append(changed, "name")
	}
	if req.Body.Description != nil {
		params.Description = pgtype.Text{String: checkDescription(*req.Body.Description, fields), Valid: true}
		changed = append(changed, "description")
	}
	if len(fields) > 0 {
		return api.UpdateProject400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(invalid("Some fields are not valid.", fields))}, nil
	}
	var out api.Project
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		p, err := q.UpdateProject(ctx, params)
		if err != nil {
			return err
		}
		if len(changed) > 0 {
			if err := s.record(ctx, req.OrgId, p.ID, "project.updated", map[string]any{"fields": changed}); err != nil {
				return err
			}
		}
		out, err = s.one(ctx, q, p)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.UpdateProject404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	return api.UpdateProject200JSONResponse(out), nil
}

// DeleteProject deletes a project and its members, then its cover.
func (s *Server) DeleteProject(ctx context.Context, req api.DeleteProjectRequestObject) (api.DeleteProjectResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.DeleteProject401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(r.body)}, nil
		}
		return api.DeleteProject403JSONResponse(r.body), nil
	}
	var gone store.Project
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if gone, err = q.GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		if _, err := q.DeleteProject(ctx, store.DeleteProjectParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		return s.record(ctx, req.OrgId, req.ProjectId, "project.deleted", nil)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.DeleteProject404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	s.dropCover(ctx, req.OrgId, gone.CoverKey)
	return api.DeleteProject204Response{}, nil
}

// dropCover deletes a cover's object. Best effort: a leftover object costs a
// little storage until the org's purge; a failed request would cost the
// person their change.
func (s *Server) dropCover(ctx context.Context, org uuid.UUID, key pgtype.Text) {
	if !key.Valid || s.deps.Files == nil {
		return
	}
	k, err := storage.ParseKey(key.String)
	if err == nil {
		err = s.deps.Files.Delete(ctx, org.String(), k)
	}
	if err != nil {
		s.logger.Warn("cover not deleted", "org_id", org, "error", err)
	}
}

// SetProjectCover names the new cover and signs its upload.
func (s *Server) SetProjectCover(ctx context.Context, req api.SetProjectCoverRequestObject) (api.SetProjectCoverResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.SetProjectCover401JSONResponse(r.body), nil
		}
		return api.SetProjectCover403JSONResponse(r.body), nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Body.ContentType))
	// The purpose decides what is allowed, before anything is signed; the
	// signed URL is then bound to exactly this type and size.
	if err := product.CoverImage.Validate(contentType, req.Body.Size); err != nil {
		return api.SetProjectCover400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(invalid("That is not a cover this accepts.",
			map[string]string{"content_type": "image/jpeg, image/png or image/webp", "size": "1 byte to 2 MB"}))}, nil
	}
	if s.deps.Files == nil {
		return nil, errors.New("no bucket is configured")
	}
	key, err := storage.NewKey(req.OrgId.String(), product.CoverImage)
	if err != nil {
		return nil, err
	}
	upload, err := s.deps.Files.UploadURL(ctx, req.OrgId.String(), key, contentType, req.Body.Size, uploadWindow)
	if err != nil {
		return nil, err
	}
	var (
		previous store.Project
		out      api.Project
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if previous, err = q.GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		p, err := q.SetCover(ctx, store.SetCoverParams{OrgID: req.OrgId, ID: req.ProjectId,
			CoverKey: pgtype.Text{String: key.String(), Valid: true}, CoverContentType: pgtype.Text{String: contentType, Valid: true}})
		if err != nil {
			return err
		}
		if err := s.record(ctx, req.OrgId, p.ID, "project.cover_set", map[string]any{"content_type": contentType, "size": req.Body.Size}); err != nil {
			return err
		}
		out, err = s.one(ctx, q, p)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetProjectCover404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	s.dropCover(ctx, req.OrgId, previous.CoverKey)
	return api.SetProjectCover200JSONResponse{UploadUrl: upload.String(), ExpiresAt: time.Now().Add(uploadWindow).UTC(), Project: out}, nil
}

// RemoveProjectCover removes the cover, and its object.
func (s *Server) RemoveProjectCover(ctx context.Context, req api.RemoveProjectCoverRequestObject) (api.RemoveProjectCoverResponseObject, error) {
	r, err := s.mayWrite(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if r.status == http.StatusUnauthorized {
			return api.RemoveProjectCover401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(r.body)}, nil
		}
		return api.RemoveProjectCover403JSONResponse(r.body), nil
	}
	var previous store.Project
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if previous, err = q.GetProject(ctx, store.GetProjectParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		if !previous.CoverKey.Valid {
			return nil
		}
		if _, err := q.SetCover(ctx, store.SetCoverParams{OrgID: req.OrgId, ID: req.ProjectId}); err != nil {
			return err
		}
		return s.record(ctx, req.OrgId, req.ProjectId, "project.cover_removed", nil)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RemoveProjectCover404JSONResponse(notFound), nil
	}
	if err != nil {
		return nil, err
	}
	s.dropCover(ctx, req.OrgId, previous.CoverKey)
	return api.RemoveProjectCover204Response{}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
