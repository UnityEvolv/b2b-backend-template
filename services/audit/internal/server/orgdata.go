package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/store"
)

// An org's audit log in its export, its purge, its retention, and a
// person's own entries. All for the organization service
// only.
//
// The table refuses every DELETE unless the transaction has set
// audit.retention to on (migrations/audit/00002). Retention and purge are
// the only two deletions, and both are asked for by the organization
// service; allowRetention is the one place that says so.

const serviceName = "audit"

// allowRetention lets this transaction's DELETEs through the append-only
// trigger. Local to the transaction, so nothing else on the connection can.
func allowRetention(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SET LOCAL audit.retention = 'on'")
	return err
}

func onlyOrganization(ctx context.Context) bool {
	return auth.RequireService(ctx, orgdata.Caller) == nil
}

const notOrganization = "The organization service only."

// exported is one entry as an export carries it.
type exported struct {
	ID         uuid.UUID      `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	SourceIP   *string        `json:"source_ip,omitempty"`
	RequestID  *string        `json:"request_id,omitempty"`
	Details    map[string]any `json:"details"`
}

func exportedOf(r row) exported {
	ev := toAPI(r.orgID, r.id, r.at, r.actor, r.action, r.targetType, r.target, r.ip, r.requestID, r.details)
	return exported{ID: ev.Id, OccurredAt: ev.OccurredAt, Actor: ev.Actor, Action: ev.Action, TargetType: ev.TargetType,
		TargetID: ev.TargetId, SourceIP: ev.SourceIp, RequestID: ev.RequestId, Details: ev.Details}
}

// dataPart is v as the contract's DataPart.
func dataPart(v any) (api.DataPart, error) {
	p, err := orgdata.Marshal(serviceName, v, nil)
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

// ExportOrgData is the org's whole audit log, oldest first.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}}, nil
	}
	events := []exported{}
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		rows, err := store.New(tx).AllAuditEvents(ctx, req.OrgId)
		for _, r := range rows {
			events = append(events, exportedOf(row{r.OrgID, r.ID, r.OccurredAt, r.Actor, r.Action, r.TargetType, r.TargetID, r.SourceIp, r.RequestID, r.Details}))
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	part, err := dataPart(map[string]any{"audit_events": events})
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(part), nil
}

// PurgeOrgData deletes the org's whole audit log, and counts what is left.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}}, nil
	}
	var remaining int64
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		if err := allowRetention(ctx, tx); err != nil {
			return err
		}
		q := store.New(tx)
		if _, err := q.PurgeAuditEvents(ctx, req.OrgId); err != nil {
			return err
		}
		var err error
		remaining, err = q.CountAuditEvents(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.PurgeOrgData200JSONResponse{Remaining: int(remaining)}, nil
}

// ExpireAuditEvents deletes the org's entries older than before: its audit
// retention, applied by the organization service's daily loop.
func (s *Server) ExpireAuditEvents(ctx context.Context, req api.ExpireAuditEventsRequestObject) (api.ExpireAuditEventsResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExpireAuditEvents403JSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}, nil
	}
	if req.Body == nil || req.Body.Before.IsZero() {
		fields := map[string]string{"before": "required, an instant"}
		return api.ExpireAuditEvents400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Say which entries to expire.", Fields: &fields}}, nil
	}
	var deleted int64
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		if err := allowRetention(ctx, tx); err != nil {
			return err
		}
		var err error
		deleted, err = store.New(tx).ExpireAuditEvents(ctx, store.ExpireAuditEventsParams{OrgID: req.OrgId, Before: req.Body.Before.UTC()})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.ExpireAuditEvents200JSONResponse{Deleted: int(deleted)}, nil
}

// ExportUserData is the entries the person made, in each org they belong
// to: as their user, or as their membership there. Entries about them made
// by someone else are the org's record, not theirs.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportUserData403JSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}, nil
	}
	var values []string
	if req.Params.Membership != nil {
		values = *req.Params.Membership
	}
	memberships, err := orgdata.ParseMemberships(values)
	if err != nil {
		fields := map[string]string{"membership": "org_id:membership_id"}
		return api.ExportUserData400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "A membership is not valid.", Fields: &fields}}, nil
	}
	type orgEvents struct {
		OrgID        uuid.UUID  `json:"org_id"`
		MembershipID uuid.UUID  `json:"membership_id"`
		Events       []exported `json:"audit_events"`
	}
	out := []orgEvents{}
	for _, m := range memberships {
		part := orgEvents{OrgID: m.OrgID, MembershipID: m.MembershipID, Events: []exported{}}
		actors := []string{"user:" + req.UserId.String(), "membership:" + m.MembershipID.String()}
		err := s.cluster.Read(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			rows, err := store.New(tx).AuditEventsByActors(ctx, store.AuditEventsByActorsParams{OrgID: m.OrgID, Actors: actors})
			for _, r := range rows {
				part.Events = append(part.Events, exportedOf(row{r.OrgID, r.ID, r.OccurredAt, r.Actor, r.Action, r.TargetType, r.TargetID, r.SourceIp, r.RequestID, r.Details}))
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, part)
	}
	part, err := dataPart(map[string]any{"organizations": out})
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(part), nil
}
