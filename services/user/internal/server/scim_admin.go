package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// The SCIM settings page's API (UO-180, UO-181): tokens, status, group
// mapping, the sync log, and halted changes. Any Owner or Admin (the
// settings permission); changing anything needs a plan with SCIM, and
// the API refuses it the same way the page does.

const (
	scimTokenGrace = 7 * 24 * time.Hour
	codeNotHalted  = "scim.not_halted"
	codeNoGroup    = "scim.group_not_found"
	codeNoToken    = "scim.token_not_found"
)

// scimAllowed is nil when the caller may see the org's SCIM settings, and,
// with change, alter them.
func (s *Server) scimAllowed(ctx context.Context, org uuid.UUID, change bool) (*api.Error, error) {
	if _, err := authz.Require(ctx, s.authz, org.String(), authz.Settings); err != nil {
		return &api.Error{Code: httpx.CodeForbidden, Message: "Only an Owner or Admin manages SCIM."}, nil
	}
	if !change {
		return nil, nil
	}
	band, err := s.plans.Band(ctx, org.String())
	if err != nil {
		return nil, err
	}
	if err := plan.CheckFeature(band, plan.SCIM); err != nil {
		if r, ok := plan.AsRefusal(err); ok {
			e := refused(r)
			return &e, nil
		}
		return nil, err
	}
	return nil, nil
}

func (s *Server) scimSettings(ctx context.Context, org uuid.UUID) (api.ScimSettings, error) {
	out := api.ScimSettings{BaseUrl: s.scimBase(org), Tokens: []api.ScimToken{}}
	band, err := s.plans.Band(ctx, org.String())
	if err != nil {
		return out, err
	}
	out.Available = plan.CheckFeature(band, plan.SCIM) == nil
	err = s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		tokens, err := q.ListScimTokens(ctx, org)
		if err != nil {
			return err
		}
		for _, t := range tokens {
			v := api.ScimToken{Id: t.ID, Prefix: t.Prefix, CreatedAt: t.CreatedAt}
			if t.LastUsedAt.Valid {
				v.LastUsedAt = &t.LastUsedAt.Time
			}
			if t.ExpiresAt.Valid {
				v.ExpiresAt = &t.ExpiresAt.Time
			}
			out.Tokens = append(out.Tokens, v)
		}
		groups, err := q.ScimGroupSummaries(ctx, org)
		if err != nil {
			return err
		}
		out.Groups = len(groups)
		st, err := q.GetScimState(ctx, org)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.LastCallAt.Valid {
			out.LastCallAt = &st.LastCallAt.Time
			out.LastOperation = textOf(st.LastOperation)
		}
		if st.HaltedAt.Valid {
			h := api.ScimHalt{At: st.HaltedAt.Time, Reason: st.HaltedReason.String, Changes: []api.ScimHaltedChange{}}
			for _, c := range decodeHalted(st.HaltedChanges) {
				v := api.ScimHaltedChange{Kind: api.ScimHaltedChangeKind(c.Kind), GroupId: c.GroupID, Memberships: c.Memberships}
				if c.GroupName != "" {
					name := c.GroupName
					v.GroupName = &name
				}
				if v.Memberships == nil {
					v.Memberships = []uuid.UUID{}
				}
				h.Changes = append(h.Changes, v)
			}
			out.Halted = &h
		}
		return nil
	})
	return out, err
}

// GetScimSettings is the org's SCIM setup and status.
func (s *Server) GetScimSettings(ctx context.Context, req api.GetScimSettingsRequestObject) (api.GetScimSettingsResponseObject, error) {
	if refusal, err := s.scimAllowed(ctx, req.OrgId, false); err != nil || refusal != nil {
		if refusal != nil {
			return api.GetScimSettings403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(*refusal)}, nil
		}
		return nil, err
	}
	out, err := s.scimSettings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetScimSettings200JSONResponse(out), nil
}

// CreateScimToken is a new token, shown in full this once. Earlier tokens
// get a week's grace, so the provider can be moved over without a gap.
func (s *Server) CreateScimToken(ctx context.Context, req api.CreateScimTokenRequestObject) (api.CreateScimTokenResponseObject, error) {
	if refusal, err := s.scimAllowed(ctx, req.OrgId, true); err != nil || refusal != nil {
		if refusal != nil {
			return api.CreateScimToken403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(*refusal)}, nil
		}
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	prefix := s.scimTokenPrefix()
	raw := prefix + base64.RawURLEncoding.EncodeToString(secret)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var t store.ScimToken
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if err := q.ExpireScimTokens(ctx, store.ExpireScimTokensParams{OrgID: req.OrgId, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(scimTokenGrace), Valid: true}}); err != nil {
			return err
		}
		var err error
		t, err = q.InsertScimToken(ctx, store.InsertScimTokenParams{OrgID: req.OrgId, ID: id, Prefix: raw[:len(prefix)+6], Hash: hashToken(raw)})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "scim.token.created", TargetType: "scim_token", TargetID: id.String(),
		Details: map[string]any{"prefix": t.Prefix}}); err != nil {
		return nil, err
	}
	return api.CreateScimToken201JSONResponse{Id: t.ID, Token: raw, Prefix: t.Prefix, CreatedAt: t.CreatedAt}, nil
}

// RevokeScimToken ends a token at once.
func (s *Server) RevokeScimToken(ctx context.Context, req api.RevokeScimTokenRequestObject) (api.RevokeScimTokenResponseObject, error) {
	// Revoking stays possible after a downgrade: closing a door is never
	// refused.
	if refusal, err := s.scimAllowed(ctx, req.OrgId, false); err != nil || refusal != nil {
		if refusal != nil {
			return api.RevokeScimToken403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(*refusal)}, nil
		}
		return nil, err
	}
	var rows int64
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).RevokeScimToken(ctx, store.RevokeScimTokenParams{OrgID: req.OrgId, ID: req.TokenId})
		return err
	})
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return api.RevokeScimToken404JSONResponse{Code: codeNoToken, Message: "No such token, or it is already revoked."}, nil
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "scim.token.revoked", TargetType: "scim_token", TargetID: req.TokenId.String()}); err != nil {
		return nil, err
	}
	return api.RevokeScimToken204Response{}, nil
}

// ListScimGroups is the groups the provider pushed, with how many people
// each holds.
func (s *Server) ListScimGroups(ctx context.Context, req api.ListScimGroupsRequestObject) (api.ListScimGroupsResponseObject, error) {
	if refusal, err := s.scimAllowed(ctx, req.OrgId, false); err != nil || refusal != nil {
		if refusal != nil {
			return api.ListScimGroups403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(*refusal)}, nil
		}
		return nil, err
	}
	var groups []store.ScimGroupSummariesRow
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		groups, err = store.New(tx).ScimGroupSummaries(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ScimGroupList{Groups: []api.ScimGroupSummary{}}
	for _, g := range groups {
		out.Groups = append(out.Groups, api.ScimGroupSummary{Id: g.ID, DisplayName: g.DisplayName, Members: int(g.Members)})
	}
	return api.ListScimGroups200JSONResponse(out), nil
}

// GetScimLog is the last hundred operations, newest first.
func (s *Server) GetScimLog(ctx context.Context, req api.GetScimLogRequestObject) (api.GetScimLogResponseObject, error) {
	if refusal, err := s.scimAllowed(ctx, req.OrgId, false); err != nil || refusal != nil {
		if refusal != nil {
			return api.GetScimLog403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(*refusal)}, nil
		}
		return nil, err
	}
	var rows []store.ScimLog
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListScimLog(ctx, store.ListScimLogParams{OrgID: req.OrgId, PageSize: 100})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ScimLog{Entries: make([]api.ScimLogEntry, 0, len(rows))}
	for _, r := range rows {
		e := api.ScimLogEntry{Id: r.ID, At: r.CreatedAt, Operation: r.Operation, Outcome: api.ScimLogEntryOutcome(r.Outcome), Error: textOf(r.Error), Details: map[string]any{}}
		_ = json.Unmarshal(r.Details, &e.Details)
		if r.MembershipID.Valid {
			id := uuid.UUID(r.MembershipID.Bytes)
			e.MembershipId = &id
		}
		if r.GroupID.Valid {
			id := uuid.UUID(r.GroupID.Bytes)
			e.GroupId = &id
		}
		out.Entries = append(out.Entries, e)
	}
	return api.GetScimLog200JSONResponse(out), nil
}

// ResolveScimHalt applies or dismisses what was halted.
func (s *Server) ResolveScimHalt(ctx context.Context, req api.ResolveScimHaltRequestObject) (api.ResolveScimHaltResponseObject, error) {
	action := req.Body.Action
	// Dismissing closes a door and stays possible on any plan; applying
	// changes who is where and needs SCIM's plan.
	if refusal, err := s.scimAllowed(ctx, req.OrgId, action == api.Apply); err != nil || refusal != nil {
		if refusal != nil {
			return api.ResolveScimHalt403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(*refusal)}, nil
		}
		return nil, err
	}
	var changes []haltedChange
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		st, err := store.New(tx).GetScimState(ctx, req.OrgId)
		if err != nil {
			return err
		}
		if st.HaltedAt.Valid {
			changes = decodeHalted(st.HaltedChanges)
		}
		return nil
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if changes == nil {
		return api.ResolveScimHalt409JSONResponse{Code: codeNotHalted, Message: "Nothing is halted."}, nil
	}
	switch action {
	case api.Apply:
		err = s.applyHalted(ctx, req.OrgId, changes)
	case api.Dismiss:
		err = s.dismissHalted(ctx, req.OrgId, changes)
	default:
		return api.ResolveScimHalt403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(invalid("Not an action.", map[string]string{"action": "apply or dismiss"}))}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		return store.New(tx).ClearScimHalt(ctx, req.OrgId)
	}); err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: map[api.ResolveScimHaltJSONBodyAction]string{api.Apply: "scim.halt.applied", api.Dismiss: "scim.halt.dismissed"}[action], TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"changes": len(changes)}}); err != nil {
		return nil, err
	}
	s.scimLog(ctx, req.OrgId, "halt "+string(action), nil, nil, "ok", "", map[string]any{"changes": len(changes)})
	out, err := s.scimSettings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.ResolveScimHalt200JSONResponse(out), nil
}
