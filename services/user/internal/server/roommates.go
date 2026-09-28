package server

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// RoomMates is what this service needs of the messaging service: the people
// someone has been in a room with, which is everyone a guest may find
// (UO-156).
type RoomMates interface {
	RoomMates(ctx context.Context, orgID, membershipID uuid.UUID) ([]uuid.UUID, error)
}

// WithRoomMates is s, asking the messaging service who a guest may find.
// Without it a guest's search finds nobody.
func (s *Server) WithRoomMates(r RoomMates) *Server {
	s.roomMates = r
	return s
}

// searchable is the memberships the caller may find: nil for everyone, or,
// for a guest, the people they have been in a room with (UO-156).
func (s *Server) searchable(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.IsService() || c.OrgID != orgID.String() {
		return nil, nil
	}
	me, err := uuid.Parse(c.MembershipID)
	if err != nil {
		return []uuid.UUID{}, nil
	}
	var row store.GetMembershipRow
	err = s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetMembership(ctx, store.GetMembershipParams{OrgID: orgID, ID: me})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return []uuid.UUID{}, nil
	}
	if err != nil {
		return nil, err
	}
	if row.Membership.Role != "guest" {
		return nil, nil
	}
	if s.roomMates == nil {
		return []uuid.UUID{}, nil
	}
	mates, err := s.roomMates.RoomMates(ctx, orgID, me)
	if err != nil {
		return nil, err
	}
	return append(mates, me), nil
}
