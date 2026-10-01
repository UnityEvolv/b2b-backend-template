package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/provider"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/store"
)

// An org's billing account in its export and its purge, and cancelling its
// subscription when it closes. All for the organization
// service only. Billing is org-level: nothing here is about one person.

const serviceName = "billing"

const notOrganization = "The organization service only."

func onlyOrganization(ctx context.Context) bool {
	return auth.RequireService(ctx, orgdata.Caller) == nil
}

// exportedAccount is the account as an export carries it. The provider's
// references are left out, and card details beyond the brand and last four
// digits never reach us at all.
type exportedAccount struct {
	Provider       string     `json:"provider"`
	Band           string     `json:"band"`
	State          string     `json:"state"`
	PeriodEnd      *time.Time `json:"period_end,omitempty"`
	PendingBand    *string    `json:"pending_band,omitempty"`
	CardBrand      *string    `json:"card_brand,omitempty"`
	CardLast4      *string    `json:"card_last4,omitempty"`
	AutoUpgrade    bool       `json:"auto_upgrade"`
	TrialUsed      bool       `json:"trial_used"`
	TrialEndsAt    *time.Time `json:"trial_ends_at,omitempty"`
	GraceStartedAt *time.Time `json:"grace_started_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastModifiedAt time.Time  `json:"last_modified_at"`
}

func textPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func timePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
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

// ExportOrgData is the org's account, or null when billing was never asked
// about it.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: forbidden(notOrganization)}, nil
	}
	var a store.Account
	found := true
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		a, err = store.New(tx).GetAccount(ctx, req.OrgId)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	data := map[string]any{"account": nil,
		"note": "Payment details are held by the payment provider; only the card brand and last four digits are kept here."}
	if found {
		data["account"] = exportedAccount{
			Provider: a.Provider, Band: a.Band, State: a.State, PeriodEnd: timePtr(a.PeriodEnd), PendingBand: textPtr(a.PendingBand),
			CardBrand: textPtr(a.CardBrand), CardLast4: textPtr(a.CardLast4), AutoUpgrade: a.AutoUpgrade, TrialUsed: a.TrialUsed,
			TrialEndsAt: timePtr(a.TrialEndsAt), GraceStartedAt: timePtr(a.GraceStartedAt), CreatedAt: a.CreatedAt, LastModifiedAt: a.LastModifiedAt,
		}
	}
	part, err := dataPart(data)
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(part), nil
}

// PurgeOrgData deletes the org's account and counts what is left. The
// provider's customer is not ours to delete; closing the org has already
// cancelled its subscription.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: forbidden(notOrganization)}, nil
	}
	var remaining int64
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.PurgeAccount(ctx, req.OrgId); err != nil {
			return err
		}
		var err error
		remaining, err = q.CountAccounts(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.PurgeOrgData200JSONResponse{Remaining: int(remaining)}, nil
}

// ExportUserData is empty: billing keeps nothing about one person.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportUserData403JSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}, nil
	}
	var values []string
	if req.Params.Membership != nil {
		values = *req.Params.Membership
	}
	if _, err := orgdata.ParseMemberships(values); err != nil {
		fields := map[string]string{"membership": "org_id:membership_id"}
		return api.ExportUserData400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "A membership is not valid.", Fields: &fields}}, nil
	}
	part, err := dataPart(map[string]any{"note": "Billing is kept per organization; nothing here is about one person."})
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(part), nil
}

// CloseAccount cancels the org's subscription at once because the org is
// closing, and records the account as cancelled on the free band. The plan
// itself is left alone: the org is closing, and the organization service is
// the one asking. An account with no subscription is a no-op, so a retry
// changes nothing.
func (s *Server) CloseAccount(ctx context.Context, req api.CloseAccountRequestObject) (api.CloseAccountResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.CloseAccount403JSONResponse{ErrorJSONResponse: forbidden(notOrganization)}, nil
	}
	var a store.Account
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		a, err = store.New(tx).GetAccount(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CloseAccount204Response{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !a.SubscriptionRef.Valid {
		return api.CloseAccount204Response{}, nil
	}
	if s.provider == nil {
		return api.CloseAccountdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: api.Error(noProvider())}, nil
	}
	ref := a.SubscriptionRef.String
	// Refused means the provider has it ended already: the account still
	// needs to say so.
	if err := s.provider.Cancel(ctx, ref); err != nil && !errors.Is(err, provider.ErrRefused) {
		return nil, err
	}
	var before store.Account
	if _, err := s.update(ctx, req.OrgId, func(x *store.Account) error {
		before = *x
		if x.SubscriptionRef.String != ref {
			return nil
		}
		x.State, x.Band = "cancelled", string(plan.Lowest())
		x.SubscriptionRef, x.ScheduleRef, x.PendingBand, x.PeriodEnd, x.GraceStartedAt = pgtype.Text{}, pgtype.Text{}, pgtype.Text{}, pgtype.Timestamptz{}, pgtype.Timestamptz{}
		x.Notices = slices.DeleteFunc(x.Notices, func(n string) bool { return strings.HasPrefix(n, "dunning:") })
		return nil
	}); err != nil {
		return nil, err
	}
	if before.SubscriptionRef.String == ref {
		if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "billing.subscription.cancelled", TargetType: "organization", TargetID: req.OrgId.String(),
			Details: map[string]any{"from": before.Band, "reason": "org_closed"}}); err != nil {
			return nil, err
		}
	}
	return api.CloseAccount204Response{}, nil
}
