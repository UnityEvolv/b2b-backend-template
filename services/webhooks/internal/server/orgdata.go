package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/store"
)

// The org data endpoints: an org's endpoints, events, deliveries and
// attempts for its export, all of it deleted for its purge. For the
// organization service only. Signing secrets never leave, sealed or not.

const notSecret = "Signing secrets are left out."

func forbidden() *failure {
	return fail(http.StatusForbidden, httpx.CodeForbidden, "For the organization service only.", nil)
}

// ExportOrgData is every row the service keeps for an org.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return forbidden(), nil
	}
	org := req.OrgId
	data := map[string]any{"omitted": notSecret}
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, t := range []struct {
			name string
			rows func(context.Context, uuid.UUID) ([][]byte, error)
		}{
			{"endpoints", q.ExportEndpoints},
			{"events", q.ExportMessages},
			{"deliveries", q.ExportDeliveries},
			{"attempts", q.ExportAttempts},
		} {
			rows, err := t.rows(ctx, org)
			if err != nil {
				return fmt.Errorf("export %s: %w", t.name, err)
			}
			out := make([]json.RawMessage, len(rows))
			for i, r := range rows {
				out[i] = r
			}
			data[t.name] = out
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	part, err := dataPart(data)
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(part), nil
}

// PurgeOrgData deletes every row of the org and counts what is left.
// Idempotent.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return forbidden(), nil
	}
	ctx = db.WithActor(ctx, db.SystemActor(serviceName))
	org := req.OrgId
	var remaining int32
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		// Deliveries and attempts go with their message and their endpoint.
		if err := q.PurgeOrgMessages(ctx, org); err != nil {
			return err
		}
		if err := q.PurgeOrgEndpoints(ctx, org); err != nil {
			return err
		}
		var err error
		remaining, err = q.CountOrgRows(ctx, org)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.PurgeOrgData200JSONResponse{Remaining: int(remaining)}, nil
}

// ExportUserData is nothing: the service keeps nothing about a person.
// Events carry ids, which the org's own export holds.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return forbidden(), nil
	}
	part, err := dataPart(map[string]any{"user_id": req.UserId, "note": "Webhooks keep nothing about a person; events carry ids and are in the organization's export."})
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(part), nil
}

// dataPart is v as the generated answer; this service has no files.
func dataPart(v any) (api.DataPart, error) {
	var out api.DataPart
	part, err := orgdata.Marshal(serviceName, v, nil)
	if err != nil {
		return out, err
	}
	b, err := json.Marshal(part)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}
