package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Exports (UO-184): an org's whole data for its Owner, or everything about
// one person for them, made by the loop rather than on request, since a
// large org's export is not a request's work, and emailed as a link.

// exportLink is how long an export's link, and its file, last.
var exportLink = storage.DataExport.Retention

const (
	exportsPerDay  = 3
	kindOrg        = "organization"
	kindPersonal   = "personal"
	exportReadme   = "README.md"
	downloadWindow = time.Hour
)

func toExport(ctx context.Context, e store.DataExport, files Files) api.DataExport {
	out := api.DataExport{Id: e.ID, Kind: api.DataExportKind(e.Kind), Status: api.DataExportStatus(e.Status), RequestedAt: e.CreatedAt}
	if e.ReadyAt.Valid {
		out.ReadyAt = &e.ReadyAt.Time
	}
	if e.ExpiresAt.Valid {
		out.ExpiresAt = &e.ExpiresAt.Time
	}
	if e.BlockedBy.Valid {
		out.BlockedBy = &e.BlockedBy.String
	}
	if e.Status == "ready" && e.ObjectKey.Valid && files != nil {
		if key, err := storage.ParseKey(e.ObjectKey.String); err == nil {
			if u, err := files.ReadURL(ctx, key.OrgID, key, downloadWindow); err == nil {
				s := u.String()
				out.DownloadUrl = &s
			}
		}
	}
	return out
}

// requestExport records an export to make, once per idempotency key and a
// few a day per person.
func (s *Server) requestExport(ctx context.Context, org uuid.UUID, kind string, user uuid.UUID, key string) (store.DataExport, bool, error) {
	c, _ := auth.CallerFrom(ctx)
	var e store.DataExport
	limited := false
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		prior, err := q.ExportByIdempotencyKey(ctx, store.ExportByIdempotencyKeyParams{OrgID: org, CreatedBy: string(c.Actor()), IdempotencyKey: pgtype.Text{String: key, Valid: true}})
		if err == nil {
			e = prior
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		n, err := q.CountRecentExports(ctx, store.CountRecentExportsParams{OrgID: org, UserID: user, Since: s.now().Add(-24 * time.Hour)})
		if err != nil {
			return err
		}
		if n >= exportsPerDay {
			limited = true
			return nil
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		e, err = q.InsertExport(ctx, store.InsertExportParams{OrgID: org, ID: id, Kind: kind, UserID: user, IdempotencyKey: pgtype.Text{String: key, Valid: key != ""}})
		return err
	})
	return e, limited, err
}

func tooMany() api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeRateLimited, Message: "Three exports a day at most. Try again tomorrow."}
}

// CreateOrgExport asks for the org's export: its Owner (or the platform).
func (s *Server) CreateOrgExport(ctx context.Context, req api.CreateOrgExportRequestObject) (api.CreateOrgExportResponseObject, error) {
	c, ok := auth.CallerFrom(ctx)
	if !ok {
		return api.CreateOrgExport401JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}), nil
	}
	if !s.isOwner(ctx, req.OrgId) {
		return api.CreateOrgExport403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only the Owner may export the organization."}), nil
	}
	user, err := uuid.Parse(c.UserID)
	if err != nil {
		return api.CreateOrgExport403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only a person may ask for an export."}), nil
	}
	if strings.TrimSpace(req.Params.IdempotencyKey) == "" {
		return api.CreateOrgExport400JSONResponse{ErrorJSONResponse: invalid("An Idempotency-Key is required.", nil)}, nil
	}
	e, limited, err := s.requestExport(ctx, req.OrgId, kindOrg, user, req.Params.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	if limited {
		return api.CreateOrgExport429JSONResponse(tooMany()), nil
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "organization.export_requested", TargetType: "export", TargetID: e.ID.String()}); err != nil {
		return nil, err
	}
	return api.CreateOrgExport202JSONResponse(toExport(ctx, e, s.off.Files)), nil
}

// ListOrgExports is the org's recent exports, for its Owner.
func (s *Server) ListOrgExports(ctx context.Context, req api.ListOrgExportsRequestObject) (api.ListOrgExportsResponseObject, error) {
	if !s.isOwner(ctx, req.OrgId) {
		return api.ListOrgExports403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only the Owner may see the organization's exports."}), nil
	}
	var rows []store.DataExport
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListOrgExports(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.DataExportList{Exports: []api.DataExport{}}
	for _, e := range rows {
		out.Exports = append(out.Exports, toExport(ctx, e, s.off.Files))
	}
	return api.ListOrgExports200JSONResponse(out), nil
}

// CreatePersonalExport asks for everything about the caller, across every
// org they belong to.
func (s *Server) CreatePersonalExport(ctx context.Context, req api.CreatePersonalExportRequestObject) (api.CreatePersonalExportResponseObject, error) {
	user, ok := personOf(ctx)
	if !ok {
		return api.CreatePersonalExport403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only a person may ask for their own export."}), nil
	}
	if strings.TrimSpace(req.Params.IdempotencyKey) == "" {
		return api.CreatePersonalExport400JSONResponse{ErrorJSONResponse: invalid("An Idempotency-Key is required.", nil)}, nil
	}
	e, limited, err := s.requestExport(ctx, uuid.MustParse(auth.PlatformOrg), kindPersonal, user, req.Params.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	if limited {
		return api.CreatePersonalExport429JSONResponse(tooMany()), nil
	}
	return api.CreatePersonalExport202JSONResponse(toExport(ctx, e, s.off.Files)), nil
}

// ListPersonalExports is the caller's own recent exports.
func (s *Server) ListPersonalExports(ctx context.Context, _ api.ListPersonalExportsRequestObject) (api.ListPersonalExportsResponseObject, error) {
	user, ok := personOf(ctx)
	if !ok {
		return api.ListPersonalExports403JSONResponse(api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Only a person has their own exports."}), nil
	}
	platform := uuid.MustParse(auth.PlatformOrg)
	var rows []store.DataExport
	err := s.cluster.Read(ctx, platform.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListExports(ctx, store.ListExportsParams{OrgID: platform, UserID: user, Kind: kindPersonal})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.DataExportList{Exports: []api.DataExport{}}
	for _, e := range rows {
		out.Exports = append(out.Exports, toExport(ctx, e, s.off.Files))
	}
	return api.ListPersonalExports200JSONResponse(out), nil
}

func personOf(ctx context.Context) (uuid.UUID, bool) {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.IsService() {
		return uuid.Nil, false
	}
	u, err := uuid.Parse(c.UserID)
	return u, err == nil
}

// isOwner is the org's Owner, or a platform operator.
func (s *Server) isOwner(ctx context.Context, org uuid.UUID) bool {
	if auth.RequirePlatform(ctx) == nil {
		return true
	}
	g, err := authz.Require(ctx, s.authz, org.String(), authz.DeleteOrganization)
	return err == nil && g.Role == authz.Owner
}

// RunExports makes waiting exports and removes expired ones: the export
// pass, run by the service's tick.
func (s *Server) RunExports(ctx context.Context) error {
	if s.off.Files == nil || s.off.Data == nil || s.off.Platform == nil {
		return nil
	}
	ctx = db.WithActor(ctx, db.SystemActor(orgdata.Caller))
	var due, expired []store.DataExport
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if due, err = q.DueExports(ctx); err != nil {
			return err
		}
		expired, err = q.ExpiredExports(ctx, pgtype.Timestamptz{Time: s.now(), Valid: true})
		return err
	})
	if err != nil {
		return err
	}
	for _, e := range expired {
		if key, err := storage.ParseKey(e.ObjectKey.String); err == nil {
			_ = s.off.Files.Delete(ctx, key.OrgID, key)
		}
		if err := s.cluster.Tx(ctx, e.OrgID.String(), func(tx pgx.Tx) error {
			return store.New(tx).MarkExportExpired(ctx, store.MarkExportExpiredParams{OrgID: e.OrgID, ID: e.ID})
		}); err != nil {
			return err
		}
	}
	var errs []error
	for _, e := range due {
		if err := s.makeExport(ctx, e); err != nil {
			// Reported with the export, by owner, and retried; the third
			// failed attempt fails it.
			attempt := store.MarkExportAttemptParams{OrgID: e.OrgID, ID: e.ID}
			var blocked *orgdata.Blocked
			if errors.As(err, &blocked) {
				attempt.BlockedBy = pgtype.Text{String: blocked.Owner, Valid: true}
			}
			s.logger.Error("export not made", "org_id", e.OrgID, "export_id", e.ID, "blocked_by", attempt.BlockedBy.String, "error", err)
			errs = append(errs, err)
			_ = s.cluster.Tx(ctx, e.OrgID.String(), func(tx pgx.Tx) error {
				return store.New(tx).MarkExportAttempt(ctx, attempt)
			})
		}
	}
	return errors.Join(errs...)
}

// makeExport gathers every service's part, writes the archive, stores it
// and emails the link.
func (s *Server) makeExport(ctx context.Context, e store.DataExport) error {
	person, err := s.off.Platform.Person(ctx, e.UserID)
	if err != nil {
		return fmt.Errorf("requester: %w", err)
	}
	var parts []orgdata.Part
	orgName := s.brand.Product
	if e.Kind == kindOrg {
		o, err := s.get(ctx, e.OrgID)
		if err != nil {
			return err
		}
		orgName = o.Name
		own, err := orgdata.Marshal(orgdata.Caller, map[string]any{"organization": toAPI(o), "retention": retention(o)}, nil)
		if err != nil {
			return err
		}
		parts = append(parts, own)
	}
	// Every exporter's part, or no export: an owner that fails blocks it.
	for _, o := range s.owners().Exporters() {
		var p orgdata.Part
		var err error
		if e.Kind == kindOrg {
			p, err = s.off.Data.Export(ctx, o, e.OrgID)
		} else {
			p, err = s.off.Data.ExportUser(ctx, o, e.UserID, person.Memberships)
		}
		if err != nil {
			return &orgdata.Blocked{Owner: o.Name, Step: "export", Err: err}
		}
		p.Service = o.Name
		parts = append(parts, p)
	}

	tmp, err := os.CreateTemp("", "export-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := s.writeArchive(ctx, tmp, e, parts); err != nil {
		return err
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	key, err := storage.NewKey(e.OrgID.String(), storage.DataExport)
	if err != nil {
		return err
	}
	if err := s.off.Files.Put(ctx, e.OrgID.String(), key, "application/zip", size, tmp); err != nil {
		return err
	}
	link, err := s.off.Files.ReadURL(ctx, e.OrgID.String(), key, exportLink)
	if err != nil {
		return err
	}
	now := s.now()
	if err := s.cluster.Tx(ctx, e.OrgID.String(), func(tx pgx.Tx) error {
		return store.New(tx).MarkExportReady(ctx, store.MarkExportReadyParams{
			OrgID: e.OrgID, ID: e.ID, ObjectKey: pgtype.Text{String: key.String(), Valid: true},
			ReadyAt: pgtype.Timestamptz{Time: now, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: now.Add(exportLink), Valid: true},
		})
	}); err != nil {
		return err
	}
	if s.deps.Email != nil && person.Email != "" {
		if _, err := s.deps.Email.Send(ctx, email.Message{
			OrgID: e.OrgID.String(), OrgName: orgName, To: person.Email, Template: "export_ready",
			Data: map[string]any{"kind": e.Kind, "link": link.String(), "days": "7"},
		}); err != nil {
			s.logger.Error("export made, link not emailed", "org_id", e.OrgID, "export_id", e.ID, "error", err)
		}
	}
	if e.Kind == kindOrg {
		_ = s.recorder.Record(ctx, audit.Event{OrgID: e.OrgID.String(), Action: "organization.export_ready", TargetType: "export", TargetID: e.ID.String()})
	}
	return nil
}

// writeArchive is the zip: a README, each service's JSON, and its files.
func (s *Server) writeArchive(ctx context.Context, w io.Writer, e store.DataExport, parts []orgdata.Part) error {
	z := zip.NewWriter(w)
	readme := []string{
		"# " + s.brand.Product + " data export",
		"",
		fmt.Sprintf("Kind: %s. Made %s.", e.Kind, s.now().UTC().Format(time.RFC3339)),
		"",
		"One folder per service. Each has data.json, that service's records as JSON,",
		"and files/ with the files that belong to them. Identifiers are UUIDs and",
		"join across files. Secrets (credentials, tokens, password hashes) are never",
		"exported.",
		"",
	}
	for _, p := range parts {
		f, err := z.Create(path.Join(p.Service, "data.json"))
		if err != nil {
			return err
		}
		var pretty any
		if err := json.Unmarshal(p.Data, &pretty); err != nil {
			pretty = map[string]any{}
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(pretty); err != nil {
			return err
		}
		readme = append(readme, fmt.Sprintf("- %s/data.json, and %d file(s) in %s/files/", p.Service, len(p.Files), p.Service))
		for _, file := range p.Files {
			key, err := storage.ParseKey(file.Key)
			if err != nil {
				continue
			}
			body, _, err := s.off.Files.Get(ctx, key.OrgID, key)
			if err != nil {
				// A file already gone (retention) is not a failed export.
				continue
			}
			dst, err := z.Create(path.Join(p.Service, "files", path.Clean("/" + file.Name)[1:]))
			if err == nil {
				_, err = io.Copy(dst, body)
			}
			body.Close()
			if err != nil {
				return err
			}
		}
	}
	f, err := z.Create(exportReadme)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, strings.Join(readme, "\n")+"\n"); err != nil {
		return err
	}
	return z.Close()
}

// RunPurges deletes closing orgs past their grace, checked service by
// service; an org any service still holds is retried the next day.
func (s *Server) RunPurges(ctx context.Context) error {
	if s.off.Data == nil || s.off.Files == nil {
		return nil
	}
	ctx = db.WithActor(ctx, db.SystemActor(orgdata.Caller))
	var orgs []uuid.UUID
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrganizationsToPurge(ctx, pgtype.Timestamptz{Time: s.now(), Valid: true})
		return err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, org := range orgs {
		if err := s.purge(ctx, org); err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
			var blocked *orgdata.Blocked
			if !errors.As(err, &blocked) {
				s.logger.Error("purge incomplete; retried tomorrow", "org_id", org, "error", err)
				continue
			}
			s.logger.Error("purge blocked; retried tomorrow", "org_id", org, "blocked_by", blocked.Owner, "error", err)
			// On the org's own record too, while it still has one: audit is
			// purged last, so it is there unless audit is what failed.
			if rerr := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "organization.purge_blocked", TargetType: "organization", TargetID: org.String(),
				Details: map[string]any{"blocked_by": blocked.Owner}}); rerr != nil {
				s.logger.Error("purge blocked, not audited", "org_id", org, "error", rerr)
			}
		}
	}
	return errors.Join(errs...)
}

// purge empties every purger, in order, each checked; the first that fails
// or still holds rows stops it, and the org stays for the next day.
func (s *Server) purge(ctx context.Context, org uuid.UUID) error {
	for _, o := range s.owners().Purgers() {
		left, err := s.off.Data.Purge(ctx, o, org)
		if err == nil && left != 0 {
			err = fmt.Errorf("%d rows remain", left)
		}
		if err != nil {
			return &orgdata.Blocked{Owner: o.Name, Step: "purge", Err: err}
		}
	}
	if _, err := s.off.Files.DeleteAll(ctx, org.String(), ""); err != nil {
		return fmt.Errorf("files: %w", err)
	}
	return s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if err := q.DeleteOrgSignups(ctx, pgtype.UUID{Bytes: org, Valid: true}); err != nil {
			return err
		}
		for _, step := range []func(context.Context, uuid.UUID) error{q.DeleteOrgExports, q.DeleteOrgDataKeys, q.DeleteOrganization} {
			if err := step(ctx, org); err != nil {
				return err
			}
		}
		left, err := q.CountOrgRows(ctx, org)
		if err != nil {
			return err
		}
		if left != 0 {
			return fmt.Errorf("organization still holds %d rows", left)
		}
		return q.RecordPurged(ctx, store.RecordPurgedParams{OrgID: org, PurgedAt: s.now()})
	})
}

// RunRetention applies each org's audit retention: events older than its
// period go.
func (s *Server) RunRetention(ctx context.Context) error {
	if s.off.Platform == nil {
		return nil
	}
	var orgs []store.OrganizationsForRetentionRow
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrganizationsForRetention(ctx)
		return err
	})
	if err != nil {
		return err
	}
	var first error
	for _, o := range orgs {
		if o.OrgID.String() == auth.PlatformOrg {
			continue
		}
		before := s.now().AddDate(0, -int(o.AuditMonths), 0)
		if err := s.off.Platform.ExpireAudit(ctx, o.OrgID, before); err != nil && first == nil {
			first = err
		}
	}
	return first
}
