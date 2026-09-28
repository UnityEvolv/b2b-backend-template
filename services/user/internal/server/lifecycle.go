package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// Account deletion (UO-184) and forgetting people who left (UO-183). A
// person asks, types DELETE, and has fourteen days to change their mind by
// signing in; then every membership is ended and anonymised, the services
// that keep something under a membership forget it, and the user row
// becomes a tombstone. A membership that ended more than thirty days ago is
// anonymised the same way; a person with nothing left is tombstoned.
// Memberships keep their ids throughout, so messages and audit entries
// still resolve, to "Former member".

const (
	deletionGrace   = 14 * 24 * time.Hour
	anonymiseAfter  = 30 * 24 * time.Hour
	deletionConfirm = "DELETE"
	codeLastOwner   = "account.last_owner"
	reasonDeleted   = "account_deleted"
)

var systemActor = db.SystemActor("user")

// WithLifecycle is s deleting people: accounts is the identity service
// (nil keeps the one from New), orgs names the org an email is sent on
// behalf of, mail sends it, and forgetters are the services that keep
// something personal under a membership.
func (s *Server) WithLifecycle(accounts Accounts, orgs OrgNames, mail email.Sender, forgetters ...Forgetter) *Server {
	if accounts != nil {
		s.accounts = accounts
	}
	s.orgNames, s.mail, s.forgetters = orgs, mail, forgetters
	return s
}

// WithClock is s telling time by now, so a test can move fourteen days on.
func (s *Server) WithClock(now func() time.Time) *Server {
	s.now = now
	return s
}

func stamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

// lastOwnerOf is the orgs a person is the last active Owner of: they may
// not be deleted until ownership is transferred.
func (s *Server) lastOwnerOf(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	var all []store.Membership
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		all, err = store.New(tx).ListMembershipsOfUser(ctx, userID)
		return err
	}); err != nil {
		return nil, err
	}
	var out []uuid.UUID
	for _, m := range all {
		if m.Role != string(authz.Owner) || m.Status != string(api.Active) {
			continue
		}
		var owners int64
		if err := s.cluster.Read(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			var err error
			owners, err = store.New(tx).CountOwners(ctx, m.OrgID)
			return err
		}); err != nil {
			return nil, err
		}
		if owners <= 1 {
			out = append(out, m.OrgID)
		}
	}
	return out, nil
}

// liveMemberships is a person's memberships not yet anonymised: the orgs
// an event about them is audited in.
func (s *Server) liveMemberships(ctx context.Context, userID uuid.UUID) ([]store.Membership, error) {
	var all []store.Membership
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		all, err = store.New(tx).ListMembershipsOfUser(ctx, userID)
		return err
	})
	out := all[:0]
	for _, m := range all {
		if !m.AnonymisedAt.Valid {
			out = append(out, m)
		}
	}
	return out, err
}

// auditOnEachOrg records an event about a person in every org they belong to.
func (s *Server) auditOnEachOrg(ctx context.Context, ms []store.Membership, action string, details map[string]any, actor db.Actor) error {
	seen := map[uuid.UUID]bool{}
	for _, m := range ms {
		if seen[m.OrgID] {
			continue
		}
		seen[m.OrgID] = true
		if err := s.recorder.Record(ctx, audit.Event{
			OrgID: m.OrgID.String(), Action: action, TargetType: "membership", TargetID: m.ID.String(),
			Details: details, Actor: actor,
		}); err != nil {
			return err
		}
	}
	return nil
}

// lastOwnerRefusal names each org in the fields.
func lastOwnerRefusal(orgs []uuid.UUID) api.Error {
	fields := map[string]string{}
	for _, o := range orgs {
		fields[o.String()] = "the last active Owner"
	}
	return api.Error{Code: codeLastOwner, Message: "Transfer ownership of every organization you are the last Owner of before deleting the account.", Fields: &fields}
}

// scheduleDeletion sets the date, once: asking again keeps the first. On the
// first ask, every org the person belongs to records it and the person is
// emailed the date.
func (s *Server) scheduleDeletion(ctx context.Context, userID uuid.UUID, preferredOrg string, details map[string]any) (store.User, []uuid.UUID, error) {
	blocked, err := s.lastOwnerOf(ctx, userID)
	if err != nil || len(blocked) > 0 {
		return store.User{}, blocked, err
	}
	now := s.now()
	var before, after store.User
	err = s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if before, err = q.GetUser(ctx, userID); err != nil {
			return err
		}
		after, err = q.RequestDeletion(ctx, store.RequestDeletionParams{At: stamp(now), After: stamp(now.Add(deletionGrace)), ID: userID})
		return err
	})
	if err != nil {
		return store.User{}, nil, err
	}
	if before.DeletionAfter.Valid {
		return after, nil, nil
	}
	ms, err := s.liveMemberships(ctx, userID)
	if err != nil {
		return store.User{}, nil, err
	}
	details["user_id"] = userID.String()
	details["deletion_after"] = after.DeletionAfter.Time.UTC().Format(time.RFC3339)
	if err := s.auditOnEachOrg(ctx, ms, "account.deletion_requested", details, ""); err != nil {
		return store.User{}, nil, err
	}
	s.sendDeletionNotice(ctx, after, ms, preferredOrg)
	return after, nil, nil
}

// sendDeletionNotice emails the date, on behalf of the org the person is
// working in or the one they used last. Best effort: the schedule stands
// either way, and the date is on their profile.
func (s *Server) sendDeletionNotice(ctx context.Context, u store.User, ms []store.Membership, preferredOrg string) {
	if s.mail == nil || s.orgNames == nil || len(ms) == 0 {
		return
	}
	org := ms[0].OrgID
	for _, m := range ms {
		if m.OrgID.String() == preferredOrg {
			org = m.OrgID
		}
	}
	name, err := s.orgNames.Name(ctx, org)
	if err != nil {
		s.logger.Error("could not name the org for a deletion notice", "error", err, "org_id", org, "user_id", u.ID)
		return
	}
	// The date in the person's own time zone, when they have one.
	loc := time.UTC
	if u.TimeZone.Valid {
		if l, err := time.LoadLocation(u.TimeZone.String); err == nil {
			loc = l
		}
	}
	if _, err := s.mail.Send(ctx, email.Message{
		OrgID: org.String(), OrgName: name, To: u.Email, Template: "account_deletion_scheduled",
		Data: map[string]any{"delete_date": u.DeletionAfter.Time.In(loc).Format("Monday, 2 January 2006")},
	}); err != nil {
		s.logger.Error("could not send a deletion notice", "error", err, "user_id", u.ID)
	}
}

// cancelDeletion clears a pending deletion; how says why, for the audit log.
func (s *Server) cancelDeletion(ctx context.Context, userID uuid.UUID, how string) error {
	var rows int64
	err := s.cluster.Tx(db.WithActor(ctx, db.UserActor(userID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).CancelDeletion(ctx, userID)
		return err
	})
	if err != nil || rows == 0 {
		return err
	}
	ms, err := s.liveMemberships(ctx, userID)
	if err != nil {
		return err
	}
	return s.auditOnEachOrg(ctx, ms, "account.deletion_cancelled", map[string]any{"user_id": userID.String(), "by": how}, db.UserActor(userID.String()))
}

func toDeletion(u store.User) api.AccountDeletion {
	return api.AccountDeletion{RequestedAt: u.DeletionRequestedAt.Time, DeletionAfter: u.DeletionAfter.Time}
}

// RequestAccountDeletion is the person asking, with DELETE typed.
func (s *Server) RequestAccountDeletion(ctx context.Context, req api.RequestAccountDeletionRequestObject) (api.RequestAccountDeletionResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok {
		return api.RequestAccountDeletion403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return api.RequestAccountDeletion403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	if req.Body.Confirm != deletionConfirm {
		return api.RequestAccountDeletion400JSONResponse{ErrorJSONResponse: invalid("Type DELETE to confirm.", map[string]string{"confirm": "DELETE, in capitals"})}, nil
	}
	u, blocked, err := s.scheduleDeletion(ctx, userID, c.OrgID, map[string]any{"requested_by": "self"})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RequestAccountDeletion403JSONResponse{Code: codeUserNotFound, Message: "No such user."}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(blocked) > 0 {
		return api.RequestAccountDeletion409JSONResponse(lastOwnerRefusal(blocked)), nil
	}
	return api.RequestAccountDeletion200JSONResponse(toDeletion(u)), nil
}

// CancelAccountDeletion is the person changing their mind.
func (s *Server) CancelAccountDeletion(ctx context.Context, _ api.CancelAccountDeletionRequestObject) (api.CancelAccountDeletionResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok {
		return api.CancelAccountDeletion403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return api.CancelAccountDeletion403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	if err := s.cancelDeletion(ctx, userID, "self"); err != nil {
		return nil, err
	}
	return api.CancelAccountDeletion204Response{}, nil
}

// ScheduleUserDeletion is a platform operator scheduling a deletion, with a
// reason recorded in every org the person belongs to.
func (s *Server) ScheduleUserDeletion(ctx context.Context, req api.ScheduleUserDeletionRequestObject) (api.ScheduleUserDeletionResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.ScheduleUserDeletion403JSONResponse{Code: httpx.CodeForbidden, Message: "Platform operators only."}, nil
	}
	reason := strings.TrimSpace(req.Body.Reason)
	if reason == "" || len(reason) > 500 {
		return api.ScheduleUserDeletion400JSONResponse{ErrorJSONResponse: invalid("Say why.", map[string]string{"reason": "1 to 500 characters"})}, nil
	}
	u, blocked, err := s.scheduleDeletion(ctx, req.UserId, "", map[string]any{"requested_by": "platform", "reason": reason})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ScheduleUserDeletion404JSONResponse{Code: codeUserNotFound, Message: "No such user."}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(blocked) > 0 {
		return api.ScheduleUserDeletion409JSONResponse(lastOwnerRefusal(blocked)), nil
	}
	return api.ScheduleUserDeletion200JSONResponse(toDeletion(u)), nil
}

// RecordUserSignedIn is a sign-in without an identity provider; like one
// with, it cancels a pending deletion.
func (s *Server) RecordUserSignedIn(ctx context.Context, req api.RecordUserSignedInRequestObject) (api.RecordUserSignedInResponseObject, error) {
	if err := auth.RequireService(ctx, "identity"); err != nil {
		return api.RecordUserSignedIn403JSONResponse{Code: httpx.CodeForbidden, Message: "The identity service only."}, nil
	}
	if err := s.cancelDeletion(ctx, req.UserId, "signed_in"); err != nil {
		return nil, err
	}
	return api.RecordUserSignedIn204Response{}, nil
}

// SetUserEmail is the identity service moving a person to an address they
// have just proven.
func (s *Server) SetUserEmail(ctx context.Context, req api.SetUserEmailRequestObject) (api.SetUserEmailResponseObject, error) {
	if err := auth.RequireService(ctx, "identity"); err != nil {
		return api.SetUserEmail403JSONResponse{Code: httpx.CodeForbidden, Message: "The identity service only."}, nil
	}
	address := normalizeEmail(req.Body.Email)
	if address == "" || len(address) > 320 {
		return api.SetUserEmail400JSONResponse{ErrorJSONResponse: invalid("Not an email address.", map[string]string{"email": "an email address"})}, nil
	}
	var u store.User
	err := s.cluster.Tx(db.WithActor(ctx, db.UserActor(req.UserId.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		u, err = store.New(tx).SetUserEmail(ctx, store.SetUserEmailParams{Email: address, ID: req.UserId})
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return api.SetUserEmail409JSONResponse{Code: "email.taken", Message: "Somebody else has that address."}, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetUserEmail404JSONResponse{Code: codeUserNotFound, Message: "No such user."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.SetUserEmail200JSONResponse(toUser(u)), nil
}

// FindUserByEmail is who has an address, for the identity service to
// refuse an email change to it.
func (s *Server) FindUserByEmail(ctx context.Context, req api.FindUserByEmailRequestObject) (api.FindUserByEmailResponseObject, error) {
	if err := auth.RequireService(ctx, "identity"); err != nil {
		return api.FindUserByEmail403JSONResponse{Code: httpx.CodeForbidden, Message: "The identity service only."}, nil
	}
	address := normalizeEmail(req.Params.Email)
	var u store.User
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		u, err = store.New(tx).GetUserByEmail(ctx, address)
		return err
	})
	if address == "" || errors.Is(err, pgx.ErrNoRows) {
		return api.FindUserByEmail404JSONResponse{Code: codeUserNotFound, Message: "No such user."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.FindUserByEmail200JSONResponse{UserId: u.ID}, nil
}

// RunHousekeeping is the daily pass, once at start and then every period.
// There is no scheduler; a deletion can be a day late.
func (s *Server) RunHousekeeping(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if err := s.Housekeeping(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("housekeeping failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Housekeeping is one pass: deletions that are due, memberships that ended
// more than thirty days ago, people with nothing left, and people a purge
// left behind. Each step goes on when another fails.
func (s *Server) Housekeeping(ctx context.Context) error {
	ctx = db.WithActor(ctx, systemActor)
	return errors.Join(s.deleteDue(ctx), s.anonymiseEnded(ctx), s.tombstoneForgotten(ctx), s.sweepOrphans(ctx))
}

// anonymiseEnded anonymises every membership that ended before the cutoff,
// one org at a time.
func (s *Server) anonymiseEnded(ctx context.Context) error {
	cutoff := stamp(s.now().Add(-anonymiseAfter))
	var orgs []uuid.UUID
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrgsWithMembershipsToAnonymise(ctx, cutoff)
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, org := range orgs {
		err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
			q := store.New(tx)
			ms, err := q.MembershipsToAnonymise(ctx, store.MembershipsToAnonymiseParams{OrgID: org, Before: cutoff})
			if err != nil {
				return err
			}
			for _, m := range ms {
				if _, err := q.AnonymiseMembership(ctx, store.AnonymiseMembershipParams{At: stamp(s.now()), OrgID: org, ID: m.ID}); err != nil {
					return err
				}
			}
			return nil
		})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// tombstoneForgotten tombstones everyone whose every membership is now
// anonymised.
func (s *Server) tombstoneForgotten(ctx context.Context) error {
	var users []store.User
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		users, err = store.New(tx).UsersToTombstone(ctx)
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, u := range users {
		errs = append(errs, s.tombstone(ctx, u))
	}
	return errors.Join(errs...)
}

// tombstone forgets a person: the identity service deletes their account
// and sessions, the photo goes, and the row keeps only its id. A failure
// leaves the row as it was, for the next pass.
func (s *Server) tombstone(ctx context.Context, u store.User) error {
	if s.accounts != nil {
		if err := s.accounts.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
	}
	s.dropPhoto(ctx, u.PhotoKey)
	return s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).TombstoneUser(ctx, store.TombstoneUserParams{At: stamp(s.now()), ID: u.ID})
		return err
	})
}

// deleteDue carries out every deletion whose fourteen days have run out.
func (s *Server) deleteDue(ctx context.Context) error {
	var due []store.User
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		due, err = store.New(tx).DeletionsDue(ctx, stamp(s.now()))
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, u := range due {
		errs = append(errs, s.deleteAccount(ctx, u))
	}
	return errors.Join(errs...)
}

// deleteAccount is one person's deletion: each membership ended and
// anonymised, each service told to forget it, each org's audit log told,
// then the person tombstoned. Safe to run again after a failure part way.
func (s *Server) deleteAccount(ctx context.Context, u store.User) error {
	// Ownership may have changed hands since they asked; an org is never
	// left without an Owner. The deletion waits until it is transferred.
	blocked, err := s.lastOwnerOf(ctx, u.ID)
	if err != nil {
		return err
	}
	if len(blocked) > 0 {
		s.logger.Warn("a due deletion waits: the person is the last Owner of an org", "user_id", u.ID, "orgs", len(blocked))
		return nil
	}
	var all []store.Membership
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		all, err = store.New(tx).ListMembershipsOfUser(ctx, u.ID)
		return err
	}); err != nil {
		return err
	}
	for _, m := range all {
		var ended, anonymised bool
		err := s.cluster.Tx(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			q := store.New(tx)
			if m.Status == string(api.Active) || m.Status == string(api.Suspended) {
				if _, err := q.SetMembershipStatus(ctx, store.SetMembershipStatusParams{Status: string(api.Deactivated), OrgID: m.OrgID, ID: m.ID}); err != nil {
					return err
				}
				ended = true
			}
			n, err := q.AnonymiseMembership(ctx, store.AnonymiseMembershipParams{At: stamp(s.now()), OrgID: m.OrgID, ID: m.ID})
			anonymised = n > 0
			return err
		})
		if err != nil {
			return err
		}
		if ended {
			s.membershipEnded(ctx, m.OrgID, m.ID, u.ID, reasonDeleted)
		}
		if anonymised {
			if err := s.recorder.Record(ctx, audit.Event{
				OrgID: m.OrgID.String(), Action: "account.deleted", TargetType: "membership", TargetID: m.ID.String(),
				Details: map[string]any{"user_id": u.ID.String()}, Actor: systemActor,
			}); err != nil {
				return err
			}
		}
		for _, f := range s.forgetters {
			if err := f.Forget(ctx, m.OrgID, m.ID); err != nil {
				s.logger.Error("a service could not forget a membership", "service", f.Name(), "error", err, "org_id", m.OrgID, "membership_id", m.ID)
				return err
			}
		}
	}
	return s.tombstone(ctx, u)
}

// sweepOrphans finishes a purge that failed part way: people with no
// membership anywhere are deleted outright.
func (s *Server) sweepOrphans(ctx context.Context) error {
	var users []store.User
	if err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		users, err = store.New(tx).ListOrphanUsers(ctx, s.now().Add(-24*time.Hour))
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, u := range users {
		errs = append(errs, s.hardDelete(ctx, u))
	}
	return errors.Join(errs...)
}

// hardDelete removes a person who belongs nowhere: their account at the
// identity service, their photo, their row.
func (s *Server) hardDelete(ctx context.Context, u store.User) error {
	if s.accounts != nil {
		if err := s.accounts.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
	}
	s.dropPhoto(ctx, u.PhotoKey)
	return s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).HardDeleteUser(ctx, u.ID)
		return err
	})
}

// The data endpoints (UO-183, UO-184), for the organization service only.

func part(v any, files []orgdata.File) (api.DataPart, error) {
	p, err := orgdata.Marshal(serviceName, v, files)
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

// name is this service, as it signs its part of an export.
const serviceName = "user"

type exportedMembership struct {
	ID            uuid.UUID       `json:"id"`
	OrgID         uuid.UUID       `json:"org_id"`
	UserID        uuid.UUID       `json:"user_id"`
	Name          string          `json:"name,omitempty"`
	DisplayName   *string         `json:"display_name,omitempty"`
	Email         string          `json:"email,omitempty"`
	Kind          string          `json:"kind"`
	Role          string          `json:"role"`
	Status        string          `json:"status"`
	Source        string          `json:"source"`
	ExternalID    *string         `json:"external_id,omitempty"`
	Directory     api.Directory   `json:"directory"`
	Attributes    json.RawMessage `json:"attributes,omitempty"`
	LastActiveAt  *time.Time      `json:"last_active_at,omitempty"`
	DeactivatedAt *time.Time      `json:"deactivated_at,omitempty"`
	AnonymisedAt  *time.Time      `json:"anonymised_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

func timeOf(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

func exportMembership(m store.Membership, u *store.User) exportedMembership {
	out := exportedMembership{
		ID: m.ID, OrgID: m.OrgID, UserID: m.UserID, Kind: m.Kind, Role: m.Role, Status: m.Status, Source: m.Source,
		ExternalID: textOf(m.ExternalID),
		Directory: api.Directory{
			JobTitle: textOf(m.JobTitle), Department: textOf(m.Department), Division: textOf(m.Division), Manager: textOf(m.Manager),
			EmployeeType: textOf(m.EmployeeType), Location: textOf(m.Location), Country: textOf(m.Country), City: textOf(m.City),
		},
		LastActiveAt: timeOf(m.LastActiveAt), DeactivatedAt: timeOf(m.DeactivatedAt), AnonymisedAt: timeOf(m.AnonymisedAt),
		CreatedAt: m.CreatedAt.UTC(),
	}
	if len(m.Attributes) > 0 && string(m.Attributes) != "{}" {
		out.Attributes = json.RawMessage(m.Attributes)
	}
	if u != nil {
		out.Name, out.Email, out.DisplayName = u.Name, u.Email, textOf(u.DisplayName)
	}
	return out
}

// ExportOrgData is the org's directory: every membership with the person's
// name and address, and the groups its provider pushed.
func (s *Server) ExportOrgData(ctx context.Context, req api.ExportOrgDataRequestObject) (api.ExportOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.ExportOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}}, nil
	}
	type group struct {
		ID          uuid.UUID   `json:"id"`
		DisplayName string      `json:"display_name"`
		ExternalID  *string     `json:"external_id,omitempty"`
		Members     []uuid.UUID `json:"membership_ids"`
		Offices     []uuid.UUID `json:"office_ids"`
	}
	out := struct {
		Memberships []exportedMembership `json:"memberships"`
		Groups      []*group             `json:"scim_groups"`
		Note        string               `json:"note"`
	}{Memberships: []exportedMembership{}, Groups: []*group{}, Note: "Secrets are not exported: SCIM tokens are left out."}
	org := req.OrgId
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		rows, err := q.ListMembershipsOfOrg(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out.Memberships = append(out.Memberships, exportMembership(r.Membership, &r.User))
		}
		groups, err := q.ListScimGroupsOfOrg(ctx, org)
		if err != nil {
			return err
		}
		byID := map[uuid.UUID]*group{}
		for _, g := range groups {
			item := &group{ID: g.ID, DisplayName: g.DisplayName, ExternalID: textOf(g.ExternalID), Members: []uuid.UUID{}, Offices: []uuid.UUID{}}
			byID[g.ID] = item
			out.Groups = append(out.Groups, item)
		}
		members, err := q.ListScimGroupMembersOfOrg(ctx, org)
		if err != nil {
			return err
		}
		for _, m := range members {
			if g := byID[m.GroupID]; g != nil {
				g.Members = append(g.Members, m.MembershipID)
			}
		}
		offices, err := q.ListGroupOffices(ctx, org)
		if err != nil {
			return err
		}
		for _, o := range offices {
			if g := byID[o.GroupID]; g != nil {
				g.Offices = append(g.Offices, o.OfficeID)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p, err := part(out, nil)
	if err != nil {
		return nil, err
	}
	return api.ExportOrgData200JSONResponse(p), nil
}

// PurgeOrgData deletes the org's memberships and SCIM records, then every
// person who now belongs nowhere, and counts what is left of the org.
// Idempotent; a person whose deletion fails here is finished by the daily
// sweep of people with no membership.
func (s *Server) PurgeOrgData(ctx context.Context, req api.PurgeOrgDataRequestObject) (api.PurgeOrgDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.PurgeOrgData403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}}, nil
	}
	org := req.OrgId
	ctx = db.WithActor(ctx, systemActor)
	var (
		people    []uuid.UUID
		remaining int64
	)
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, step := range []func(context.Context, uuid.UUID) (int64, error){
			q.DeleteScimGroupMembersOfOrg, q.DeleteScimGroupOfficesOfOrg, q.DeleteScimGroupsOfOrg,
			q.DeleteScimLogOfOrg, q.DeleteScimStateOfOrg, q.DeleteScimTokensOfOrg,
		} {
			if _, err := step(ctx, org); err != nil {
				return err
			}
		}
		var err error
		if people, err = q.DeleteMembershipsOfOrg(ctx, org); err != nil {
			return err
		}
		remaining, err = q.CountOrgRows(ctx, org)
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, id := range people {
		var u store.User
		var left int64
		err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
			q := store.New(tx)
			var err error
			if left, err = q.CountMembershipsOfUser(ctx, id); err != nil || left > 0 {
				return err
			}
			u, err = q.GetUserAny(ctx, id)
			return err
		})
		if err == nil && left == 0 {
			err = s.hardDelete(ctx, u)
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error("could not delete a person left with no membership", "error", err, "user_id", id)
		}
	}
	return api.PurgeOrgData200JSONResponse{Remaining: int(remaining)}, nil
}

// ExportUserData is what this service keeps about one person: their
// profile and preferences, and each of their memberships.
func (s *Server) ExportUserData(ctx context.Context, req api.ExportUserDataRequestObject) (api.ExportUserDataResponseObject, error) {
	if err := auth.RequireService(ctx, orgdata.Caller); err != nil {
		return api.ExportUserData403JSONResponse{Code: httpx.CodeForbidden, Message: "The organization service only."}, nil
	}
	if req.Params.Membership != nil {
		if _, err := orgdata.ParseMemberships(*req.Params.Membership); err != nil {
			return api.ExportUserData400JSONResponse{ErrorJSONResponse: invalid("Not a membership.", map[string]string{"membership": "org_id:membership_id"})}, nil
		}
	}
	type profile struct {
		ID                  uuid.UUID       `json:"id"`
		Email               string          `json:"email"`
		Name                string          `json:"name"`
		DisplayName         *string         `json:"display_name,omitempty"`
		TimeZone            *string         `json:"time_zone,omitempty"`
		WorkingHours        json.RawMessage `json:"working_hours,omitempty"`
		Theme               string          `json:"theme"`
		Language            *string         `json:"language,omitempty"`
		HideDecorations     bool            `json:"hide_decorations"`
		CreatedAt           time.Time       `json:"created_at"`
		DeletionRequestedAt *time.Time      `json:"deletion_requested_at,omitempty"`
		DeletionAfter       *time.Time      `json:"deletion_after,omitempty"`
	}
	out := struct {
		User        *profile             `json:"user"`
		Memberships []exportedMembership `json:"memberships"`
	}{Memberships: []exportedMembership{}}
	var files []orgdata.File
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		u, err := q.GetUserAny(ctx, req.UserId)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.User = &profile{
			ID: u.ID, Email: u.Email, Name: u.Name, DisplayName: textOf(u.DisplayName), TimeZone: textOf(u.TimeZone),
			Theme: u.Theme, Language: textOf(u.Language), HideDecorations: u.HideDecorations, CreatedAt: u.CreatedAt.UTC(),
			DeletionRequestedAt: timeOf(u.DeletionRequestedAt), DeletionAfter: timeOf(u.DeletionAfter),
		}
		if len(u.WorkingHours) > 0 {
			out.User.WorkingHours = json.RawMessage(u.WorkingHours)
		}
		if u.PhotoKey.Valid {
			files = append(files, orgdata.File{Key: u.PhotoKey.String, Name: "profile-photo"})
		}
		ms, err := q.ListMembershipsOfUser(ctx, req.UserId)
		if err != nil {
			return err
		}
		for _, m := range ms {
			out.Memberships = append(out.Memberships, exportMembership(m, nil))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p, err := part(out, files)
	if err != nil {
		return nil, err
	}
	return api.ExportUserData200JSONResponse(p), nil
}
