package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// The org data endpoints: an org's notification rows for
// its export, deleted for its purge, a person's own for theirs, and a
// membership's forgotten for account deletion. For the organization service
// only, and forgetting for the user service too.
//
// No secret leaves: a device goes out without its push token (an FCM
// registration or a web push endpoint and keys), the token's hash and the
// session it was registered in; an email without its bodies and its
// unsubscribe link, which carry sign-in and one-click links.

const serviceName = "notification"

// notSecret says what the export leaves out, in the export itself.
const notSecret = "Push tokens, web push endpoints and keys, session ids and email bodies are left out."

// ExportOrgData is every row the service keeps for an org.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: forbidden("For the organization service only.")}, nil
	}
	org := req.OrgId
	data := map[string]any{"omitted": notSecret}
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, t := range []struct {
			name string
			rows func(context.Context, uuid.UUID) ([][]byte, error)
		}{
			{"org_settings", q.ExportOrgSettings},
			{"preferences", q.ExportPreferences},
			{"feed_entries", q.ExportFeed},
			{"devices", q.ExportDevices},
			{"held", q.ExportHeld},
			{"daily_counts", q.ExportDailyCounts},
			{"emails", q.ExportOutbox},
		} {
			rows, err := t.rows(ctx, org)
			if err != nil {
				return fmt.Errorf("export %s: %w", t.name, err)
			}
			data[t.name] = raw(rows)
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

// PurgeOrgData deletes every row of the org, outbox included, and counts
// what is left. Idempotent.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: forbidden("For the organization service only.")}, nil
	}
	ctx = db.WithActor(ctx, db.SystemActor(serviceName))
	org := req.OrgId
	var remaining int32
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, del := range []func(context.Context, uuid.UUID) error{
			q.PurgeOrgHeld, q.PurgeOrgFeed, q.PurgeOrgDevices, q.PurgeOrgPreferences,
			q.PurgeOrgSettings, q.PurgeOrgDailyCounts, q.PurgeOrgOutbox,
		} {
			if err := del(ctx, org); err != nil {
				return err
			}
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

// ExportUserData is one person's preferences, feed and devices in each of
// their memberships.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.ExportUserData403JSONResponse(forbidden("For the organization service only.")), nil
	}
	var values []string
	if req.Params.Membership != nil {
		values = *req.Params.Membership
	}
	memberships, err := orgdata.ParseMemberships(values)
	if err != nil {
		return api.ExportUserData400JSONResponse{ErrorJSONResponse: invalid("A membership is not valid.", map[string]string{"membership": "org_id:membership_id"})}, nil
	}
	type membershipData struct {
		OrgID        uuid.UUID         `json:"org_id"`
		MembershipID uuid.UUID         `json:"membership_id"`
		Preferences  []json.RawMessage `json:"preferences"`
		Feed         []json.RawMessage `json:"feed_entries"`
		Devices      []json.RawMessage `json:"devices"`
	}
	out := struct {
		UserID      uuid.UUID        `json:"user_id"`
		Omitted     string           `json:"omitted"`
		Memberships []membershipData `json:"memberships"`
	}{UserID: req.UserId, Omitted: notSecret, Memberships: []membershipData{}}
	for _, m := range memberships {
		d := membershipData{OrgID: m.OrgID, MembershipID: m.MembershipID}
		err := s.cluster.Read(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			q := store.New(tx)
			var err error
			var rows [][]byte
			if rows, err = q.ExportMemberPreferences(ctx, store.ExportMemberPreferencesParams{OrgID: m.OrgID, MembershipID: m.MembershipID}); err != nil {
				return err
			}
			d.Preferences = raw(rows)
			if rows, err = q.ExportMemberFeed(ctx, store.ExportMemberFeedParams{OrgID: m.OrgID, MembershipID: m.MembershipID}); err != nil {
				return err
			}
			d.Feed = raw(rows)
			if rows, err = q.ExportMemberDevices(ctx, store.ExportMemberDevicesParams{OrgID: m.OrgID, MembershipID: m.MembershipID}); err != nil {
				return err
			}
			d.Devices = raw(rows)
			return nil
		})
		if err != nil {
			return nil, err
		}
		out.Memberships = append(out.Memberships, d)
	}
	part, err := dataPart(out)
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(part), nil
}

// ForgetMembershipData deletes what is kept under one membership: its
// preferences, its feed, its devices and anything held for it. The org's
// counts stay; they name no one.
func (s *Server) ForgetMembershipData(ctx context.Context, req api.ForgetMembershipDataRequestObject) (api.ForgetMembershipDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller, orgdata.Eraser); err != nil {
		return api.ForgetMembershipData403JSONResponse{ErrorJSONResponse: forbidden("For the organization and user services only.")}, nil
	}
	ctx = db.WithActor(ctx, db.SystemActor(serviceName))
	org, mbr := req.OrgId, req.MembershipId
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if err := q.ForgetMemberHeld(ctx, store.ForgetMemberHeldParams{OrgID: org, MembershipID: mbr}); err != nil {
			return err
		}
		if err := q.ForgetMemberFeed(ctx, store.ForgetMemberFeedParams{OrgID: org, MembershipID: mbr}); err != nil {
			return err
		}
		if _, err := q.DeleteMemberDevices(ctx, store.DeleteMemberDevicesParams{OrgID: org, MembershipID: mbr}); err != nil {
			return err
		}
		return q.ForgetMemberPreferences(ctx, store.ForgetMemberPreferencesParams{OrgID: org, MembershipID: mbr})
	})
	if err != nil {
		return nil, err
	}
	return api.ForgetMembershipData204Response{}, nil
}

// raw is JSON rows as they are, never null.
func raw(rows [][]byte) []json.RawMessage {
	out := make([]json.RawMessage, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out
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
