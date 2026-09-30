package server

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

const (
	defaultPage = 50
	maxPage     = 200
)

// normalizeEmail is the stored form of an address, or "" when it is not one.
func normalizeEmail(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	parsed, err := mail.ParseAddress(s)
	if err != nil || parsed.Address != s {
		return ""
	}
	return s
}

// localPart is the name to give a user nobody has named yet.
func localPart(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}

// admit is the plan's word on one more member in the org. A guest does not
// count, and neither does anyone already in.
func (s *Server) admit(ctx context.Context, q *store.Queries, orgID uuid.UUID, kind string) (*plan.Refusal, error) {
	if kind != string(api.Member) {
		return nil, nil
	}
	// The platform org is not a customer: it has no record in the
	// organization service and no plan, and its operators are staff, never
	// counted against a cap or billed. Without this the first operator's
	// invite (identity's bootstrap) could never be accepted.
	if strings.EqualFold(orgID.String(), auth.PlatformOrg) {
		return nil, nil
	}
	band, err := s.plans.Band(ctx, orgID.String())
	if err != nil {
		return nil, err
	}
	active, err := q.CountActiveMemberships(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if err := plan.CheckUsers(band, int(active)); err != nil {
		// Past the cap: billing upgrades where the org has that on, and
		// only then is the member let in.
		if s.capacity != nil {
			ok, cerr := s.capacity.MakeRoom(ctx, orgID, int(active)+1)
			if cerr != nil {
				return nil, cerr
			}
			if ok {
				return nil, nil
			}
		}
		r, _ := plan.AsRefusal(err)
		return r, nil
	}
	if s.capacity != nil {
		s.capacity.MembersChanged(ctx, orgID, int(active)+1)
	}
	return nil, nil
}

func refused(r *plan.Refusal) api.Error {
	fields := r.Fields()
	return api.Error{Code: plan.Code, Message: r.Message, Fields: &fields}
}

// RecordSignIn is a person authenticating through an org's identity
// provider. The provider is the gate: first sign-in makes the membership;
// every sign-in refreshes what the provider says about them.
func (s *Server) RecordSignIn(ctx context.Context, req api.RecordSignInRequestObject) (api.RecordSignInResponseObject, error) {
	if err := auth.RequireService(ctx, "identity"); err != nil {
		return api.RecordSignIn403JSONResponse{Code: httpx.CodeForbidden, Message: "The identity service only."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	email := normalizeEmail(body.Email)
	if email == "" {
		fields["email"] = "an email address"
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 200 {
		fields["name"] = "1 to 200 characters"
	}
	if len(fields) > 0 {
		return api.RecordSignIn400JSONResponse{ErrorJSONResponse: invalid("Some fields are not valid.", fields)}, nil
	}
	dir := fromDirectory(body.Directory, body.IdpSubject)

	var (
		user     store.User
		m        store.Membership
		all      []store.Membership
		created  bool
		inactive string
		refusal  *plan.Refusal
		noOrg    bool
	)
	err := s.cluster.Tx(ctx, body.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		var madeUser bool
		user, madeUser, err = findOrCreateUser(ctx, q, email, name)
		if err != nil {
			return err
		}
		if !madeUser && user.Name != name {
			// The provider is authoritative for the name it sends.
			if user, err = q.UpdateUserName(ctx, store.UpdateUserNameParams{Name: name, ID: user.ID}); err != nil {
				return err
			}
		}
		row, err := q.GetMembershipByUser(ctx, store.GetMembershipByUserParams{OrgID: body.OrgId, UserID: user.ID})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			refusal, err = s.admit(ctx, q, body.OrgId, string(api.Member))
			if errors.Is(err, plan.ErrNoOrganization) {
				noOrg = true
				return nil
			}
			if err != nil || refusal != nil {
				return err
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			m, err = q.InsertMembership(ctx, store.InsertMembershipParams{
				OrgID: body.OrgId, ID: id, UserID: user.ID, Kind: string(api.Member), Role: "user", Source: string(api.Idp),
				IdpSubject: dir.idpSubject, JobTitle: dir.jobTitle, Department: dir.department, Division: dir.division, Manager: dir.manager,
				EmployeeType: dir.employeeType, Location: dir.location, Country: dir.country, City: dir.city, Attributes: dir.attributes,
			})
			if err != nil {
				return err
			}
			created = true
			if _, err := q.TouchMembership(ctx, store.TouchMembershipParams{OrgID: body.OrgId, ID: id}); err != nil {
				return err
			}
		case err != nil:
			return err
		case row.Membership.Status != string(api.Active):
			inactive = row.Membership.Status
			return nil
		default:
			m, err = q.UpdateMembershipDirectory(ctx, store.UpdateMembershipDirectoryParams{
				IdpSubject: dir.idpSubject, JobTitle: dir.jobTitle, Department: dir.department, Division: dir.division, Manager: dir.manager,
				EmployeeType: dir.employeeType, Location: dir.location, Country: dir.country, City: dir.city, Attributes: dir.attributes,
				OrgID: body.OrgId, ID: row.Membership.ID,
			})
			if err != nil {
				return err
			}
		}
		all, err = q.ListMembershipsOfUser(ctx, user.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if noOrg {
		return api.RecordSignIn400JSONResponse{ErrorJSONResponse: invalid("No such organization.", map[string]string{"org_id": "unknown"})}, nil
	}
	if refusal != nil {
		return api.RecordSignIn403JSONResponse(refused(refusal)), nil
	}
	if inactive != "" {
		return api.RecordSignIn409JSONResponse{Code: codeInactive, Message: "This membership is " + inactive + "."}, nil
	}
	if created {
		if err := s.recordCreated(ctx, m); err != nil {
			return nil, err
		}
	}
	// Signing in cancels a pending account deletion.
	if user.DeletionAfter.Valid {
		if err := s.cancelDeletion(ctx, user.ID, "signed_in"); err != nil {
			return nil, err
		}
	}
	return api.RecordSignIn200JSONResponse(api.SignInResult{
		User: toUser(user), Membership: toMembership(m, user), Memberships: s.withUser(all, user),
	}), nil
}

func (s *Server) withUser(ms []store.Membership, u store.User) []api.Membership {
	out := make([]api.Membership, 0, len(ms))
	for _, m := range ms {
		out = append(out, toMembership(m, u))
	}
	return out
}

func (s *Server) recordCreated(ctx context.Context, m store.Membership) error {
	return s.recorder.Record(ctx, audit.Event{
		OrgID: m.OrgID.String(), Action: "membership.created",
		TargetType: "membership", TargetID: m.ID.String(),
		Details: map[string]any{"user_id": m.UserID.String(), "kind": m.Kind, "role": m.Role, "source": m.Source},
	})
}

// CreateMembership is the other ways in: an invite, a bulk import, the
// self-serve owner. Never a second account for a known email.
func (s *Server) CreateMembership(ctx context.Context, req api.CreateMembershipRequestObject) (api.CreateMembershipResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.CreateMembership403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	email := normalizeEmail(body.Email)
	if email == "" {
		fields["email"] = "an email address"
	}
	kind := string(api.Member)
	if body.Kind != nil {
		kind = string(*body.Kind)
	}
	if kind != string(api.Member) && kind != string(api.Guest) {
		fields["kind"] = "member or guest"
	}
	switch body.Source {
	case api.Invite, api.Import, api.Owner:
	default:
		fields["source"] = "invite, import or owner"
	}
	// The role: from the caller, a fixed one; the self-serve owner is the
	// Owner, a guest is a Guest.
	role := string(authz.User)
	if body.Role != nil && strings.TrimSpace(*body.Role) != "" {
		if _, err := authz.ParseRole(strings.TrimSpace(*body.Role)); err != nil {
			fields["role"] = "owner, admin, billing_admin, user or guest"
		}
		role = strings.TrimSpace(*body.Role)
	}
	if body.Source == api.Owner {
		role = string(authz.Owner)
	}
	if kind == string(api.Guest) {
		role = string(authz.Guest)
	}
	name := localPart(email)
	if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
		name = strings.TrimSpace(*body.Name)
	}
	if len(name) > 200 {
		fields["name"] = "up to 200 characters"
	}
	if len(fields) > 0 {
		return api.CreateMembership400JSONResponse{ErrorJSONResponse: invalid("Some fields are not valid.", fields)}, nil
	}

	var (
		user    store.User
		m       store.Membership
		created bool
		refusal *plan.Refusal
		noOrg   bool
	)
	err := s.cluster.Tx(ctx, body.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		user, _, err = findOrCreateUser(ctx, q, email, name)
		if err != nil {
			return err
		}
		row, err := q.GetMembershipByUser(ctx, store.GetMembershipByUserParams{OrgID: body.OrgId, UserID: user.ID})
		if err == nil && row.Membership.Status == statusLeft {
			// They left; a fresh invite brings the same membership back on
			// the new terms, once the plan admits one more.
			refusal, err = s.admit(ctx, q, body.OrgId, kind)
			if errors.Is(err, plan.ErrNoOrganization) {
				noOrg = true
				return nil
			}
			if err != nil || refusal != nil {
				return err
			}
			m, err = q.RejoinMembership(ctx, store.RejoinMembershipParams{Role: role, Kind: kind, Source: string(body.Source), OrgID: body.OrgId, ID: row.Membership.ID})
			created = err == nil
			return err
		}
		if err == nil {
			// Already in: the same answer as the first call, never a second row.
			m = row.Membership
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		refusal, err = s.admit(ctx, q, body.OrgId, kind)
		if errors.Is(err, plan.ErrNoOrganization) {
			noOrg = true
			return nil
		}
		if err != nil || refusal != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		m, err = q.InsertMembership(ctx, store.InsertMembershipParams{
			OrgID: body.OrgId, ID: id, UserID: user.ID, Kind: kind, Role: role, Source: string(body.Source), Attributes: []byte("{}"),
		})
		created = err == nil
		return err
	})
	if err != nil {
		return nil, err
	}
	if noOrg {
		return api.CreateMembership400JSONResponse{ErrorJSONResponse: invalid("No such organization.", map[string]string{"org_id": "unknown"})}, nil
	}
	if refusal != nil {
		return api.CreateMembership403JSONResponse(refused(refusal)), nil
	}
	if created {
		if err := s.recordCreated(ctx, m); err != nil {
			return nil, err
		}
	}
	return api.CreateMembership201JSONResponse(toMembership(m, user)), nil
}

// ListUserMemberships is every org a person belongs to, most recently
// active first: what the identity service reads to decide where a sign-in
// lands, and the organization service reads to reach a person for a notice
// or build their own export.
func (s *Server) ListUserMemberships(ctx context.Context, req api.ListUserMembershipsRequestObject) (api.ListUserMembershipsResponseObject, error) {
	if err := auth.RequireService(ctx, "identity", "organization"); err != nil {
		return api.ListUserMemberships403JSONResponse{Code: httpx.CodeForbidden, Message: "The identity and organization services only."}, nil
	}
	var (
		user store.User
		all  []store.Membership
	)
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if user, err = q.GetUser(ctx, req.UserId); err != nil {
			return err
		}
		all, err = q.ListMembershipsOfUser(ctx, req.UserId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ListUserMemberships200JSONResponse{Memberships: []api.Membership{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.ListUserMemberships200JSONResponse{Memberships: s.withUser(all, user)}, nil
}

// GetMe is the caller: their user, and the membership their session carries.
func (s *Server) GetMe(ctx context.Context, _ api.GetMeRequestObject) (api.GetMeResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok {
		return api.GetMe403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return api.GetMe404JSONResponse{Code: codeUserNotFound, Message: "No such user."}, nil
	}
	var (
		user store.User
		row  store.GetMembershipRow
		has  bool
	)
	err = s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if user, err = q.GetUser(ctx, userID); err != nil {
			return err
		}
		if c.MembershipID == "" || c.OrgID == "" {
			return nil
		}
		orgID, err1 := uuid.Parse(c.OrgID)
		mID, err2 := uuid.Parse(c.MembershipID)
		if err1 != nil || err2 != nil {
			return nil
		}
		row, err = q.GetMembership(ctx, store.GetMembershipParams{OrgID: orgID, ID: mID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		has = err == nil
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetMe404JSONResponse{Code: codeUserNotFound, Message: "No such user."}, nil
	}
	if err != nil {
		return nil, err
	}
	me := api.Me{User: s.profile(ctx, user)}
	if user.DeletionAfter.Valid {
		after := user.DeletionAfter.Time
		me.DeletionAfter = &after
	}
	if has && row.Membership.UserID == user.ID {
		m := toMembership(row.Membership, row.User)
		me.Membership = &m
	}
	return api.GetMe200JSONResponse(me), nil
}

// ListMemberships is one org's memberships for its people and the platform:
// cursor paginated, sorted by name or by when they joined, searched and
// filtered. Which members may see the whole list is the role check. The
// notification service reads it too, for who an admin event reaches.
func (s *Server) ListMemberships(ctx context.Context, req api.ListMembershipsRequestObject) (api.ListMembershipsResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil && auth.RequireService(ctx, "notification") != nil {
		return api.ListMemberships403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	p := req.Params
	fields := map[string]string{}
	if p.Sort != nil && *p.Sort != api.Name && *p.Sort != api.CreatedAt {
		fields["sort"] = "name or created_at"
	}
	if p.Order != nil && *p.Order != api.Asc && *p.Order != api.Desc {
		fields["order"] = "asc or desc"
	}
	if p.Status != nil && *p.Status != api.Active && *p.Status != api.Deactivated && *p.Status != api.Suspended {
		fields["status"] = "active, deactivated or suspended"
	}
	if len(fields) > 0 {
		return api.ListMemberships400JSONResponse{ErrorJSONResponse: invalid("Some parameters are not valid.", fields)}, nil
	}
	limit := httpx.PageSize(p.Limit, defaultPage, maxPage)
	byCreated := p.Sort != nil && *p.Sort == api.CreatedAt
	descending := byCreated
	if p.Order != nil {
		descending = *p.Order == api.Desc
	}
	var cursor httpx.Cursor
	if p.Cursor != nil {
		c, ok, err := httpx.DecodeCursor(*p.Cursor)
		if err != nil || (ok && byCreated == (c.Key != "")) {
			return api.ListMemberships400JSONResponse{ErrorJSONResponse: invalid("The cursor is not valid.", map[string]string{"cursor": "not a cursor this list issued"})}, nil
		}
		cursor = c
	}
	var status pgtype.Text
	if p.Status != nil {
		status = pgtype.Text{String: string(*p.Status), Valid: true}
	}
	q := text(p.Q)
	if q.Valid {
		q.String = strings.TrimSpace(q.String)
	}

	only, err := s.searchable(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}

	type row struct {
		m store.Membership
		u store.User
	}
	var rows []row
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		qs := store.New(tx)
		if byCreated {
			out, err := qs.ListMembershipsByCreated(ctx, store.ListMembershipsByCreatedParams{
				OrgID: req.OrgId, Status: status, Role: text(p.Role), Department: text(p.Department), Q: q, OnlyIds: only,
				Descending: descending, PageSize: int32(limit + 1),
				AfterAt: pgtype.Timestamptz{Time: cursor.At, Valid: !cursor.At.IsZero()}, AfterID: pgtype.UUID{Bytes: cursor.ID, Valid: !cursor.At.IsZero()},
			})
			for _, r := range out {
				rows = append(rows, row{r.Membership, r.User})
			}
			return err
		}
		out, err := qs.ListMembershipsByName(ctx, store.ListMembershipsByNameParams{
			OrgID: req.OrgId, Status: status, Role: text(p.Role), Department: text(p.Department), Q: q, OnlyIds: only,
			Descending: descending, PageSize: int32(limit + 1),
			AfterName: text(&cursor.Key), AfterID: pgtype.UUID{Bytes: cursor.ID, Valid: cursor.Key != ""},
		})
		for _, r := range out {
			rows = append(rows, row{r.Membership, r.User})
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	page := api.MembershipPage{Memberships: make([]api.Membership, 0, len(rows))}
	for i, r := range rows {
		if i == limit {
			last := rows[i-1]
			next := httpx.Cursor{ID: last.m.ID}
			if byCreated {
				next.At = last.m.CreatedAt
			} else {
				next.Key = strings.ToLower(last.u.Name)
			}
			encoded := next.Encode()
			page.NextCursor = &encoded
			break
		}
		page.Memberships = append(page.Memberships, toMembership(r.m, r.u))
	}
	return api.ListMemberships200JSONResponse(page), nil
}

// GetMembership is one membership, to the org's people, the platform, and
// the services (the authorization service reads the role from here).
func (s *Server) GetMembership(ctx context.Context, req api.GetMembershipRequestObject) (api.GetMembershipResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil && auth.RequireService(ctx) != nil {
		return api.GetMembership403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var row store.GetMembershipRow
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetMembership(ctx, store.GetMembershipParams{OrgID: req.OrgId, ID: req.MembershipId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetMembership404JSONResponse{Code: codeNotFound, Message: "No such membership."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetMembership200JSONResponse(toMembership(row.Membership, row.User)), nil
}

// SetMembershipStatus deactivates, suspends or reactivates one membership.
// The person's other orgs are untouched. Needs the users permission (an
// Owner, or an Admin with user management), and an Admin may only manage
// Users and Guests; a platform operator always may. Audited.
func (s *Server) SetMembershipStatus(ctx context.Context, req api.SetMembershipStatusRequestObject) (api.SetMembershipStatusResponseObject, error) {
	grant, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users)
	if err != nil {
		return api.SetMembershipStatus403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to change memberships."}, nil
	}
	to := req.Body.Status
	if to != api.Active && to != api.Deactivated && to != api.Suspended {
		return api.SetMembershipStatus400JSONResponse{ErrorJSONResponse: invalid("Not a status.", map[string]string{"status": "active, deactivated or suspended"})}, nil
	}
	var (
		before    store.GetMembershipRow
		after     store.Membership
		outranked bool
		lastOwner bool
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if before, err = q.GetMembership(ctx, store.GetMembershipParams{OrgID: req.OrgId, ID: req.MembershipId}); err != nil {
			return err
		}
		if !authz.MayManage(grant.Role, authz.Role(before.Membership.Role)) {
			outranked = true
			return nil
		}
		if before.Membership.Status == string(to) {
			after = before.Membership
			return nil
		}
		// An org can never lock itself out: the last active Owner stays active.
		if before.Membership.Role == string(authz.Owner) && to != api.Active {
			owners, err := q.CountOwners(ctx, req.OrgId)
			if err != nil {
				return err
			}
			if owners <= 1 {
				lastOwner = true
				return nil
			}
		}
		after, err = q.SetMembershipStatus(ctx, store.SetMembershipStatusParams{Status: string(to), OrgID: req.OrgId, ID: req.MembershipId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetMembershipStatus404JSONResponse{Code: codeNotFound, Message: "No such membership."}, nil
	}
	if err != nil {
		return nil, err
	}
	if outranked {
		return api.SetMembershipStatus403JSONResponse{Code: httpx.CodeForbidden, Message: "An Admin manages Users and Guests only."}, nil
	}
	if lastOwner {
		return api.SetMembershipStatus409JSONResponse{Code: "membership.last_owner", Message: "The organization must keep at least one active Owner."}, nil
	}
	if before.Membership.Status != after.Status {
		err := s.recorder.Record(ctx, audit.Event{
			OrgID: req.OrgId.String(), Action: "membership.status_changed",
			TargetType: "membership", TargetID: req.MembershipId.String(),
			Details: map[string]any{"user_id": after.UserID.String(), "from": before.Membership.Status, "to": after.Status},
		})
		if err != nil {
			return nil, err
		}
		// Access ends now, not at the next token refresh: the sessions
		// carrying this membership move or end, and any socket open in this
		// org is told why and closed.
		if to != api.Active {
			s.membershipEnded(ctx, req.OrgId, req.MembershipId, after.UserID, string(to))
		}
	}
	return api.SetMembershipStatus200JSONResponse(toMembership(after, before.User)), nil
}

// searchable is the memberships the caller may find: nil for everyone, or,
// for a guest, only themselves. A guest is a collaborator from outside the
// org and does not browse its people; a product that gives guests a wider
// view widens this.
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
	return []uuid.UUID{me}, nil
}
