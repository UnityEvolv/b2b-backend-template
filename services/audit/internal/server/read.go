package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/store"
)

// Reading the log: the org's own entries, to whoever holds its audit
// permission, and to platform operators for the org detail page. A page at
// a time newest or oldest first, or every match as CSV for a compliance
// request.

// maxExport is the most rows one export carries. A request that needs more
// narrows the dates.
const maxExport = 50_000

var errNotPermitted = errors.New("not permitted")

// mayRead is nil when the caller may read org's log: a platform operator, or
// a member whose role has the audit permission.
func (s *Server) mayRead(ctx context.Context, orgID string) error {
	if auth.RequirePlatform(ctx) == nil {
		return nil
	}
	// A person's token must be for this org; an API key's org is checked by
	// authz.Require with its groups.
	if _, isKey := auth.KeyFrom(ctx); !isKey && auth.RequireOrg(ctx, orgID) != nil {
		return errNotPermitted
	}
	if _, err := authz.Require(ctx, s.authz, orgID, authz.Audit); err != nil {
		if errors.Is(err, authz.ErrForbidden) || errors.Is(err, auth.ErrForbidden) {
			return errNotPermitted
		}
		return err
	}
	return nil
}

// filters is what both reads narrow by.
type filters struct {
	action, actor, targetType, targetID pgtype.Text
	from, to                            pgtype.Timestamptz
}

func textOf(v *string) pgtype.Text {
	if v == nil || *v == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *v, Valid: true}
}

func instantOf(v *time.Time) pgtype.Timestamptz {
	if v == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *v, Valid: true}
}

// row is one entry, whichever query read it.
type row struct {
	orgID, id                         uuid.UUID
	at                                time.Time
	actor, action, targetType, target string
	ip                                *netip.Addr
	requestID                         pgtype.Text
	details                           []byte
}

// read is up to limit entries after the cursor, in order.
func (s *Server) read(ctx context.Context, orgID uuid.UUID, f filters, oldestFirst bool, cursor *httpx.Cursor, limit int) ([]row, error) {
	var out []row
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if oldestFirst {
			p := store.ListAuditEventsOldestFirstParams{
				OrgID: orgID, Limit: int32(limit),
				ActionPrefix: f.action, Actor: f.actor, TargetType: f.targetType, TargetID: f.targetID,
				FromAt: f.from, ToAt: f.to,
			}
			if cursor != nil {
				p.AfterAt = pgtype.Timestamptz{Time: cursor.At, Valid: true}
				p.AfterID = pgtype.UUID{Bytes: cursor.ID, Valid: true}
			}
			rows, err := q.ListAuditEventsOldestFirst(ctx, p)
			for _, r := range rows {
				out = append(out, row{r.OrgID, r.ID, r.OccurredAt, r.Actor, r.Action, r.TargetType, r.TargetID, r.SourceIp, r.RequestID, r.Details})
			}
			return err
		}
		p := store.ListAuditEventsParams{
			OrgID: orgID, Limit: int32(limit),
			ActionPrefix: f.action, Actor: f.actor, TargetType: f.targetType, TargetID: f.targetID,
			FromAt: f.from, ToAt: f.to,
		}
		if cursor != nil {
			p.BeforeAt = pgtype.Timestamptz{Time: cursor.At, Valid: true}
			p.BeforeID = pgtype.UUID{Bytes: cursor.ID, Valid: true}
		}
		rows, err := q.ListAuditEvents(ctx, p)
		for _, r := range rows {
			out = append(out, row{r.OrgID, r.ID, r.OccurredAt, r.Actor, r.Action, r.TargetType, r.TargetID, r.SourceIp, r.RequestID, r.Details})
		}
		return err
	})
	return out, err
}

func badRange(from, to *time.Time) bool {
	return from != nil && to != nil && !from.Before(*to)
}

// ListAuditEvents is one page of an org's entries.
func (s *Server) ListAuditEvents(ctx context.Context, req api.ListAuditEventsRequestObject) (api.ListAuditEventsResponseObject, error) {
	if err := s.mayRead(ctx, req.OrgId.String()); err != nil {
		if errors.Is(err, errNotPermitted) {
			return api.ListAuditEvents403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to read the audit log."}, nil
		}
		return nil, err
	}
	p := req.Params
	if badRange(p.From, p.To) {
		fields := map[string]string{"to": "after from"}
		return api.ListAuditEvents400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The date range ends before it starts.", Fields: &fields}}, nil
	}
	limit := httpx.PageSize(p.Limit, defaultPage, maxPage)
	var cursor *httpx.Cursor
	if p.Cursor != nil {
		c, ok, err := httpx.DecodeCursor(*p.Cursor)
		if err != nil {
			fields := map[string]string{"cursor": "not a cursor this service issued"}
			return api.ListAuditEvents400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The cursor is not valid.", Fields: &fields}}, nil
		}
		if ok {
			cursor = &c
		}
	}
	f := filters{textOf(p.Action), textOf(p.Actor), textOf(p.TargetType), textOf(p.TargetId), instantOf(p.From), instantOf(p.To)}
	oldest := p.Order != nil && *p.Order == api.Oldest
	rows, err := s.read(ctx, req.OrgId, f, oldest, cursor, limit+1)
	if err != nil {
		return nil, err
	}
	page := api.AuditEventPage{Events: make([]api.AuditEvent, 0, len(rows))}
	for i, r := range rows {
		if i == limit {
			// One more than asked for was fetched: there is another page.
			last := rows[i-1]
			next := httpx.Cursor{At: last.at, ID: last.id}.Encode()
			page.NextCursor = &next
			break
		}
		page.Events = append(page.Events, toAPI(r.orgID, r.id, r.at, r.actor, r.action, r.targetType, r.target, r.ip, r.requestID, r.details))
	}
	return api.ListAuditEvents200JSONResponse(page), nil
}

// ExportAuditEvents is every matching entry as CSV, oldest first.
func (s *Server) ExportAuditEvents(ctx context.Context, req api.ExportAuditEventsRequestObject) (api.ExportAuditEventsResponseObject, error) {
	if err := s.mayRead(ctx, req.OrgId.String()); err != nil {
		if errors.Is(err, errNotPermitted) {
			return api.ExportAuditEvents403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to read the audit log."}, nil
		}
		return nil, err
	}
	p := req.Params
	if badRange(p.From, p.To) {
		fields := map[string]string{"to": "after from"}
		return api.ExportAuditEvents400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The date range ends before it starts.", Fields: &fields}}, nil
	}
	f := filters{textOf(p.Action), textOf(p.Actor), textOf(p.TargetType), textOf(p.TargetId), instantOf(p.From), instantOf(p.To)}
	rows, err := s.read(ctx, req.OrgId, f, true, nil, maxExport+1)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxExport {
		fields := map[string]string{"from": "a narrower range"}
		return api.ExportAuditEvents400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: "audit.export_too_large", Message: "More than 50,000 entries match. Narrow the dates and export in parts.", Fields: &fields}}, nil
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"occurred_at", "actor", "action", "target_type", "target_id", "source_ip", "request_id", "details"})
	for _, r := range rows {
		ip := ""
		if r.ip != nil {
			ip = r.ip.String()
		}
		_ = w.Write([]string{r.at.UTC().Format(time.RFC3339), r.actor, r.action, r.targetType, r.target, ip, r.requestID.String, string(r.details)})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return api.ExportAuditEvents200TextcsvResponse{Body: &buf, ContentLength: int64(buf.Len())}, nil
}
