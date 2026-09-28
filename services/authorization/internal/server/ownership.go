package server

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/store"
)

// Ownership transfer (UO-86): ownership moves to another member who
// accepts, never dumped on someone unaware. This is the escape hatch for
// the last-Owner rule: an Owner who wants to leave transfers first.

const (
	transferTTL = 7 * 24 * time.Hour

	codeTransferNotOpen = "ownership_transfer.not_open"
	codeTransferMissing = "ownership_transfer.not_found"
	codeNotEligible     = "ownership_transfer.not_eligible"
)

func transferStatus(row store.OwnershipTransfer, now time.Time) api.OwnershipTransferStatus {
	switch {
	case row.AcceptedAt.Valid:
		return api.Accepted
	case row.CancelledAt.Valid:
		return api.Cancelled
	case now.After(row.ExpiresAt):
		return api.Expired
	}
	return api.Pending
}

func toTransfer(row store.OwnershipTransfer) api.OwnershipTransfer {
	out := api.OwnershipTransfer{
		TransferId: row.ID, OrgId: row.OrgID, FromMembershipId: row.FromMembershipID, ToMembershipId: row.ToMembershipID,
		Status: transferStatus(row, time.Now()), ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
	}
	if row.AcceptedAt.Valid {
		out.AcceptedAt = &row.AcceptedAt.Time
	}
	return out
}

// caller is the member making the request, by their token.
func callerMembership(ctx context.Context, orgID uuid.UUID) (uuid.UUID, bool) {
	if err := auth.RequireOrg(ctx, orgID.String()); err != nil {
		return uuid.Nil, false
	}
	c, _ := auth.CallerFrom(ctx)
	id, err := uuid.Parse(c.MembershipID)
	return id, err == nil
}

// notify queues an email on the org's behalf. Not being able to is logged,
// not fatal: the transfer is recorded and shows in the app either way.
func (s *Server) notify(ctx context.Context, orgID uuid.UUID, to, template string, data map[string]any) {
	if s.email == nil || to == "" {
		return
	}
	orgName := ""
	if s.orgs != nil {
		name, err := s.orgs.Name(ctx, orgID)
		if err != nil {
			s.logger.Warn("could not read the org's name for an email", "error", err, "org_id", orgID)
			return
		}
		orgName = name
	}
	if _, err := s.email.Send(ctx, email.Message{OrgID: orgID.String(), OrgName: orgName, To: to, Template: template, Data: data}); err != nil {
		s.logger.Warn("could not queue an ownership email", "error", err, "org_id", orgID)
	}
}

// RequestOwnershipTransfer is an Owner asking another member to take over.
func (s *Server) RequestOwnershipTransfer(ctx context.Context, req api.RequestOwnershipTransferRequestObject) (api.RequestOwnershipTransferResponseObject, error) {
	from, ok := callerMembership(ctx, req.OrgId)
	if !ok {
		return api.RequestOwnershipTransfer403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	initiator, err := s.memberships.Get(ctx, req.OrgId, from)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err != nil || initiator.Role != authz.Owner || initiator.Status != "active" {
		return api.RequestOwnershipTransfer403JSONResponse{Code: authz.Code, Message: "Only an Owner may transfer ownership."}, nil
	}
	to := req.Body.ToMembershipId
	if to == from {
		fields := map[string]string{"to_membership_id": "another member"}
		return api.RequestOwnershipTransfer400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "You are the Owner already.", Fields: &fields}}, nil
	}
	target, err := s.memberships.Get(ctx, req.OrgId, to)
	if errors.Is(err, ErrNotFound) {
		return api.RequestOwnershipTransfer404JSONResponse{Code: "membership.not_found", Message: "No such member."}, nil
	}
	if err != nil {
		return nil, err
	}
	if target.Status != "active" || target.Role == authz.Guest || target.Kind == "guest" {
		return api.RequestOwnershipTransfer400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: codeNotEligible, Message: "Ownership goes to an active member of the organization, not a guest."}}, nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var row store.OwnershipTransfer
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		// One open request at a time: a new one replaces whatever waited.
		if _, err := q.CancelOpenOwnershipTransfers(ctx, req.OrgId); err != nil {
			return err
		}
		var err error
		row, err = q.InsertOwnershipTransfer(ctx, store.InsertOwnershipTransferParams{OrgID: req.OrgId, ID: id, FromMembershipID: from, ToMembershipID: to, ExpiresAt: time.Now().Add(transferTTL)})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "ownership.transfer_requested", TargetType: "membership", TargetID: to.String(),
		Details: map[string]any{"transfer_id": id.String(), "from_membership_id": from.String(), "expires_at": row.ExpiresAt},
	}); err != nil {
		return nil, err
	}
	link := s.apps["admin"] + "/settings/ownership"
	s.notify(ctx, req.OrgId, target.Email, "ownership_transfer_requested", map[string]any{"link": link, "days": int(transferTTL.Hours() / 24)})
	return api.RequestOwnershipTransfer201JSONResponse(toTransfer(row)), nil
}

// ListOwnershipTransfers is the open request, to its two parties.
func (s *Server) ListOwnershipTransfers(ctx context.Context, req api.ListOwnershipTransfersRequestObject) (api.ListOwnershipTransfersResponseObject, error) {
	me, ok := callerMembership(ctx, req.OrgId)
	if !ok {
		return api.ListOwnershipTransfers403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var rows []store.OwnershipTransfer
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).OpenOwnershipTransfers(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ListOwnershipTransfers200JSONResponse{Transfers: []api.OwnershipTransfer{}}
	for _, row := range rows {
		if row.FromMembershipID == me || row.ToMembershipID == me {
			out.Transfers = append(out.Transfers, toTransfer(row))
		}
	}
	return out, nil
}

// AcceptOwnershipTransfer is the person asked taking ownership: they become
// Owner, the previous Owner becomes an Admin, both are told.
func (s *Server) AcceptOwnershipTransfer(ctx context.Context, req api.AcceptOwnershipTransferRequestObject) (api.AcceptOwnershipTransferResponseObject, error) {
	me, ok := callerMembership(ctx, req.OrgId)
	if !ok {
		return api.AcceptOwnershipTransfer403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var row store.OwnershipTransfer
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetOwnershipTransfer(ctx, store.GetOwnershipTransferParams{OrgID: req.OrgId, ID: req.TransferId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.AcceptOwnershipTransfer404JSONResponse{Code: codeTransferMissing, Message: "No such request."}, nil
	}
	if err != nil {
		return nil, err
	}
	if row.ToMembershipID != me {
		return api.AcceptOwnershipTransfer403JSONResponse{Code: httpx.CodeForbidden, Message: "Only the person asked may accept."}, nil
	}
	if transferStatus(row, time.Now()) != api.Pending {
		return api.AcceptOwnershipTransfer409JSONResponse{Code: codeTransferNotOpen, Message: "This request is no longer open."}, nil
	}
	// The initiator must still be the Owner and the target still an active
	// member: the org may have changed in the days between.
	initiator, err := s.memberships.Get(ctx, req.OrgId, row.FromMembershipID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	target, err2 := s.memberships.Get(ctx, req.OrgId, me)
	if err2 != nil && !errors.Is(err2, ErrNotFound) {
		return nil, err2
	}
	if err != nil || err2 != nil || initiator.Role != authz.Owner || initiator.Status != "active" || target.Status != "active" {
		return api.AcceptOwnershipTransfer409JSONResponse{Code: codeTransferNotOpen, Message: "The organization changed since this request was made; ask for a new one."}, nil
	}
	// Spend the request first, so two clicks do not transfer twice; then
	// the new Owner, then the old one demoted, which the last-Owner rule
	// now allows.
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).AcceptOwnershipTransfer(ctx, store.AcceptOwnershipTransferParams{OrgID: req.OrgId, ID: req.TransferId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.AcceptOwnershipTransfer409JSONResponse{Code: codeTransferNotOpen, Message: "This request is no longer open."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.memberships.SetRole(ctx, req.OrgId, me, authz.Owner); err != nil {
		return nil, err
	}
	if err := s.memberships.SetRole(ctx, req.OrgId, row.FromMembershipID, authz.Admin); err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "ownership.transferred", TargetType: "membership", TargetID: me.String(),
		Details: map[string]any{"transfer_id": row.ID.String(), "from_membership_id": row.FromMembershipID.String(), "previous_owner_role": string(authz.Admin)},
	}); err != nil {
		return nil, err
	}
	s.notify(ctx, req.OrgId, target.Email, "ownership_transferred", map[string]any{"line": "You are now its Owner."})
	s.notify(ctx, req.OrgId, initiator.Email, "ownership_transferred", map[string]any{"line": "You are now an Admin."})
	return api.AcceptOwnershipTransfer200JSONResponse(toTransfer(row)), nil
}

// CancelOwnershipTransfer is the Owner withdrawing, or the target declining.
func (s *Server) CancelOwnershipTransfer(ctx context.Context, req api.CancelOwnershipTransferRequestObject) (api.CancelOwnershipTransferResponseObject, error) {
	me, ok := callerMembership(ctx, req.OrgId)
	if !ok {
		return api.CancelOwnershipTransfer403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var row store.OwnershipTransfer
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetOwnershipTransfer(ctx, store.GetOwnershipTransferParams{OrgID: req.OrgId, ID: req.TransferId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CancelOwnershipTransfer404JSONResponse{Code: codeTransferMissing, Message: "No such request."}, nil
	}
	if err != nil {
		return nil, err
	}
	if row.FromMembershipID != me && row.ToMembershipID != me {
		return api.CancelOwnershipTransfer403JSONResponse{Code: httpx.CodeForbidden, Message: "Only the Owner who asked or the person asked may end this request."}, nil
	}
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).CancelOwnershipTransfer(ctx, store.CancelOwnershipTransferParams{OrgID: req.OrgId, ID: req.TransferId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CancelOwnershipTransfer404JSONResponse{Code: codeTransferNotOpen, Message: "This request is no longer open."}, nil
	}
	if err != nil {
		return nil, err
	}
	action := "ownership.transfer_cancelled"
	if row.ToMembershipID == me {
		action = "ownership.transfer_declined"
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: action, TargetType: "membership", TargetID: row.ToMembershipID.String(),
		Details: map[string]any{"transfer_id": row.ID.String()},
	}); err != nil {
		return nil, err
	}
	return api.CancelOwnershipTransfer204Response{}, nil
}
