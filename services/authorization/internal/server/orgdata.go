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
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/store"
)

// An org's permission configuration and ownership transfers in its export
// and its purge, and the transfers a person started or was offered in their
// own export. All for the organization service only. Roles
// themselves live on the membership, in the user service.

const serviceName = "authorization"

const notOrganization = "The organization service only."

func onlyOrganization(ctx context.Context) bool {
	return auth.RequireService(ctx, orgdata.Caller) == nil
}

type exportedConfig struct {
	AdminPermissions        []string  `json:"admin_permissions"`
	BillingAdminPermissions []string  `json:"billing_admin_permissions"`
	LastModifiedBy          string    `json:"last_modified_by"`
	LastModifiedAt          time.Time `json:"last_modified_at"`
}

type exportedTransfer struct {
	ID               uuid.UUID  `json:"id"`
	FromMembershipID uuid.UUID  `json:"from_membership_id"`
	ToMembershipID   uuid.UUID  `json:"to_membership_id"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	AcceptedAt       *time.Time `json:"accepted_at,omitempty"`
	CancelledAt      *time.Time `json:"cancelled_at,omitempty"`
}

func transfersOf(rows []store.OwnershipTransfer) []exportedTransfer {
	out := make([]exportedTransfer, 0, len(rows))
	for _, r := range rows {
		t := exportedTransfer{ID: r.ID, FromMembershipID: r.FromMembershipID, ToMembershipID: r.ToMembershipID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
		if r.AcceptedAt.Valid {
			t.AcceptedAt = &r.AcceptedAt.Time
		}
		if r.CancelledAt.Valid {
			t.CancelledAt = &r.CancelledAt.Time
		}
		out = append(out, t)
	}
	return out
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

// ExportOrgData is the org's permission configuration (absent when it is on
// the defaults) and every ownership transfer.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}}, nil
	}
	var configs []store.PermissionConfig
	var transfers []store.OwnershipTransfer
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if configs, err = q.ExportPermissionConfigs(ctx, req.OrgId); err != nil {
			return err
		}
		transfers, err = q.ExportOwnershipTransfers(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	data := map[string]any{"permission_config": nil, "ownership_transfers": transfersOf(transfers)}
	if len(configs) > 0 {
		c := configs[0]
		data["permission_config"] = exportedConfig{AdminPermissions: c.AdminPermissions, BillingAdminPermissions: c.BillingAdminPermissions,
			LastModifiedBy: c.LastModifiedBy, LastModifiedAt: c.LastModifiedAt}
	}
	part, err := dataPart(data)
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(part), nil
}

// PurgeOrgData deletes the org's transfers and configuration, and counts
// what is left.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if !onlyOrganization(ctx) {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: notOrganization}}, nil
	}
	var remaining int32
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.PurgeOwnershipTransfers(ctx, req.OrgId); err != nil {
			return err
		}
		if _, err := q.PurgePermissionConfigs(ctx, req.OrgId); err != nil {
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

// ExportUserData is the ownership transfers each of the person's
// memberships started or was offered.
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
	type orgTransfers struct {
		OrgID        uuid.UUID          `json:"org_id"`
		MembershipID uuid.UUID          `json:"membership_id"`
		Transfers    []exportedTransfer `json:"ownership_transfers"`
	}
	out := []orgTransfers{}
	for _, m := range memberships {
		var rows []store.OwnershipTransfer
		err := s.cluster.Read(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			var err error
			rows, err = store.New(tx).OwnershipTransfersOfMembership(ctx, store.OwnershipTransfersOfMembershipParams{OrgID: m.OrgID, MembershipID: m.MembershipID})
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, orgTransfers{OrgID: m.OrgID, MembershipID: m.MembershipID, Transfers: transfersOf(rows)})
	}
	part, err := dataPart(map[string]any{"organizations": out})
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(part), nil
}
