package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// The SCIM endpoint: what an org's identity provider calls, at
// /scim/v2/{org_id}, with the org's own bearer token instead of a session.
// Everything it does is audited as the identity provider's action.

// scimActor is who SCIM changes are attributed to, in provenance and audit.
var scimActor = db.SystemActor("scim")

// scimHandler answers one SCIM operation; a *scimProblem error is shown to
// the provider as it is, anything else is a 500.
type scimHandler func(w http.ResponseWriter, r *http.Request, org uuid.UUID) error

// WithSCIM is s with the public base the SCIM URL is shown under, such as
// the user service's address on the API host; empty makes locations
// relative.
func (s *Server) WithSCIM(publicBase string) *Server {
	s.scimPublic = strings.TrimRight(publicBase, "/")
	return s
}

// scimBase is the org's SCIM base URL.
func (s *Server) scimBase(org uuid.UUID) string {
	return s.scimPublic + "/scim/v2/" + org.String()
}

// SCIM is the endpoint's routes. It sits outside the session middleware and
// the per-address limit: providers call from shared addresses, so the
// limit is per org instead.
func (s *Server) SCIM(limiter *ratelimit.Limiter) http.Handler {
	mux := http.NewServeMux()
	handle := func(method, resource string, h scimHandler) {
		var next http.Handler = s.scimAuth(method+" "+strings.SplitN(resource, "/", 2)[0], h)
		if limiter != nil {
			next = limiter.Wrap(ratelimit.On(ratelimit.SCIM, byPathOrg), next)
		}
		mux.Handle(method+" /scim/v2/{org}/"+resource, next)
	}
	handle(http.MethodGet, "ServiceProviderConfig", func(w http.ResponseWriter, _ *http.Request, org uuid.UUID) error {
		writeSCIM(w, http.StatusOK, serviceProviderConfig(s.scimBase(org)+"/ServiceProviderConfig"))
		return nil
	})
	handle(http.MethodGet, "ResourceTypes", func(w http.ResponseWriter, _ *http.Request, org uuid.UUID) error {
		all := resourceTypes(s.scimBase(org))
		writeSCIM(w, http.StatusOK, listResponse(all, len(all), 1))
		return nil
	})
	handle(http.MethodGet, "ResourceTypes/{id}", func(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
		return writeOne(w, resourceTypes(s.scimBase(org)), r.PathValue("id"))
	})
	handle(http.MethodGet, "Schemas", func(w http.ResponseWriter, _ *http.Request, org uuid.UUID) error {
		all := schemas(s.scimBase(org))
		writeSCIM(w, http.StatusOK, listResponse(all, len(all), 1))
		return nil
	})
	handle(http.MethodGet, "Schemas/{id}", func(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
		return writeOne(w, schemas(s.scimBase(org)), r.PathValue("id"))
	})
	handle(http.MethodGet, "Users", s.scimListUsers)
	handle(http.MethodPost, "Users", s.scimCreateUser)
	handle(http.MethodGet, "Users/{id}", s.scimGetUser)
	handle(http.MethodPut, "Users/{id}", s.scimReplaceUser)
	handle(http.MethodPatch, "Users/{id}", s.scimPatchUser)
	handle(http.MethodDelete, "Users/{id}", s.scimDeleteUser)
	handle(http.MethodGet, "Groups", s.scimListGroups)
	handle(http.MethodPost, "Groups", s.scimCreateGroup)
	handle(http.MethodGet, "Groups/{id}", s.scimGetGroup)
	handle(http.MethodPut, "Groups/{id}", s.scimReplaceGroup)
	handle(http.MethodPatch, "Groups/{id}", s.scimPatchGroup)
	handle(http.MethodDelete, "Groups/{id}", s.scimDeleteGroup)
	mux.HandleFunc("/scim/", func(w http.ResponseWriter, _ *http.Request) {
		writeProblem(w, &scimProblem{status: http.StatusNotFound, detail: "No such SCIM resource."})
	})
	return mux
}

func byPathOrg(r *http.Request) (string, bool) {
	org := r.PathValue("org")
	return "scim:" + org, org != ""
}

func writeOne(w http.ResponseWriter, all []any, id string) error {
	for _, x := range all {
		if strings.EqualFold(str(get(x.(map[string]any), "id")), id) {
			writeSCIM(w, http.StatusOK, x)
			return nil
		}
	}
	return &scimProblem{status: http.StatusNotFound, detail: "No such resource."}
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// scimAuth is the org's token, a plan with SCIM, and the record of the
// call, in front of every operation.
func (s *Server) scimAuth(operation string, h scimHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		org, err := uuid.Parse(r.PathValue("org"))
		if err != nil {
			writeProblem(w, &scimProblem{status: http.StatusNotFound, detail: "No such organization."})
			return
		}
		ctx := db.WithActor(r.Context(), scimActor)
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		raw = strings.TrimSpace(raw)
		var token store.ScimToken
		if ok && raw != "" {
			err = s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
				var err error
				token, err = store.New(tx).ScimTokenByHash(ctx, store.ScimTokenByHashParams{OrgID: org, Hash: hashToken(raw)})
				return err
			})
		}
		if !ok || raw == "" || errors.Is(err, pgx.ErrNoRows) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeProblem(w, &scimProblem{status: http.StatusUnauthorized, detail: "The token is not valid for this organization."})
			return
		}
		if err != nil {
			s.scimFailed(w, r, err)
			return
		}
		ent, err := s.plans.Entitlements(ctx, org.String())
		if errors.Is(err, plan.ErrNoOrganization) {
			writeProblem(w, &scimProblem{status: http.StatusNotFound, detail: "No such organization."})
			return
		}
		if err != nil {
			s.scimFailed(w, r, err)
			return
		}
		if err := ent.CheckFeature(plan.SCIM); err != nil {
			detail := "This organization's plan does not include SCIM provisioning."
			if ref, ok := plan.AsRefusal(err); ok {
				detail = ref.Message
			}
			writeProblem(w, &scimProblem{status: http.StatusForbidden, detail: detail})
			return
		}
		if err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
			q := store.New(tx)
			if err := q.TouchScimToken(ctx, store.TouchScimTokenParams{OrgID: org, ID: token.ID}); err != nil {
				return err
			}
			return q.TouchScimState(ctx, store.TouchScimStateParams{OrgID: org, Operation: pgtype.Text{String: operation, Valid: true}})
		}); err != nil {
			s.scimFailed(w, r, err)
			return
		}
		if err := h(w, r.WithContext(ctx), org); err != nil {
			var p *scimProblem
			if errors.As(err, &p) {
				writeProblem(w, p)
				return
			}
			s.scimFailed(w, r, err)
		}
	})
}

func (s *Server) scimFailed(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("scim request failed", "route", r.Pattern, "error", err)
	writeProblem(w, &scimProblem{status: http.StatusInternalServerError, detail: "Something went wrong; try again."})
}

// log records one SCIM operation for the settings page's sync log. It is
// the page's record, not the audit trail, so a failure here is logged and
// the operation stands.
func (s *Server) scimLog(ctx context.Context, org uuid.UUID, operation string, membership, group *uuid.UUID, outcome, problem string, details map[string]any) {
	id, err := uuid.NewV7()
	if err != nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	raw, _ := json.Marshal(details)
	p := store.InsertScimLogParams{OrgID: org, ID: id, Operation: operation, Outcome: outcome, Details: raw}
	if membership != nil {
		p.MembershipID = pgtype.UUID{Bytes: *membership, Valid: true}
	}
	if group != nil {
		p.GroupID = pgtype.UUID{Bytes: *group, Valid: true}
	}
	if problem != "" {
		if len(problem) > 500 {
			problem = problem[:500]
		}
		p.Error = pgtype.Text{String: problem, Valid: true}
	}
	if err := s.cluster.Tx(db.WithActor(ctx, scimActor), org.String(), func(tx pgx.Tx) error {
		return store.New(tx).InsertScimLog(ctx, p)
	}); err != nil {
		s.logger.Warn("scim log not written", "org_id", org, "error", err)
	}
}

// ---- Users ----------------------------------------------------------------

// userResource is a membership as a SCIM user: what the provider last sent,
// with what this service owns (id, active, meta) laid over it.
func (s *Server) userResource(m store.Membership, u store.User) map[string]any {
	res := map[string]any{}
	if len(m.Scim) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(m.Scim)))
		dec.UseNumber()
		_ = dec.Decode(&res)
	}
	for _, k := range []string{"_deleted", "id", "meta", "schemas", "active", "externalId"} {
		del(res, k)
	}
	kinds := []string{schemaUser}
	if get(res, schemaEnterprise) != nil {
		kinds = append(kinds, schemaEnterprise)
	}
	res["schemas"] = kinds
	res["id"] = m.ID.String()
	if m.ExternalID.Valid {
		res["externalId"] = m.ExternalID.String
	}
	if str(get(res, "userName")) == "" {
		set(res, "userName", u.Email)
	}
	if get(res, "emails") == nil {
		res["emails"] = []any{map[string]any{"value": u.Email, "type": "work", "primary": true}}
	}
	if get(res, "name") == nil {
		res["name"] = map[string]any{"formatted": u.Name}
	}
	if get(res, "displayName") == nil {
		res["displayName"] = u.Name
	}
	res["active"] = m.Status == string(api.Active)
	res["meta"] = map[string]any{
		"resourceType": "User",
		"created":      m.CreatedAt.UTC().Format(time.RFC3339),
		"lastModified": m.LastModifiedAt.UTC().Format(time.RFC3339),
		"location":     s.scimBase(m.OrgID) + "/Users/" + m.ID.String(),
	}
	return res
}

// saveUser stores what the provider says about m. activeSaid is whether
// this request said anything about active; the provider's last word on it
// is what the reconciliation holds status to.
func saveUser(ctx context.Context, q *store.Queries, m store.Membership, res map[string]any, activeSaid bool) (store.Membership, error) {
	f := userFieldsOf(res)
	kept := cloneResource(res)
	for _, k := range []string{"id", "meta", "schemas", "active", "externalId"} {
		del(kept, k)
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return m, err
	}
	attrs, err := json.Marshal(f.attributes)
	if err != nil {
		return m, err
	}
	said := m.ScimActive
	if activeSaid && f.active != nil {
		said = pgtype.Bool{Bool: *f.active, Valid: true}
	}
	return q.SetMembershipScim(ctx, store.SetMembershipScimParams{
		ExternalID: text(&f.externalID), Scim: raw, ScimActive: said,
		JobTitle: text(&f.jobTitle), Department: text(&f.department), Division: text(&f.division), Manager: text(&f.manager),
		EmployeeType: text(&f.employeeType), Location: text(&f.location), Country: text(&f.country), City: text(&f.city),
		Attributes: attrs, OrgID: m.OrgID, ID: m.ID,
	})
}

// errRefusedByPlan rolls a transaction back when the plan refused.
var errRefusedByPlan = errors.New("refused by the plan")

// statusChange is a membership moving between active and deactivated.
type statusChange struct {
	from, to string
}

// setActive moves m to active or deactivated as the provider says.
// Suspended is an admin's decision and stays. An Owner is never
// deactivated by SCIM. A reactivation counts against the plan's user cap.
func (s *Server) setActive(ctx context.Context, q *store.Queries, m store.Membership, active bool) (store.Membership, *statusChange, *plan.Refusal, error) {
	switch {
	case active && m.Status == string(api.Deactivated):
		refusal, err := s.admit(ctx, q, m.OrgID, m.Kind)
		if err != nil || refusal != nil {
			return m, nil, refusal, err
		}
		after, err := q.SetMembershipStatus(ctx, store.SetMembershipStatusParams{Status: string(api.Active), OrgID: m.OrgID, ID: m.ID})
		return after, &statusChange{m.Status, after.Status}, nil, err
	case !active && m.Status == string(api.Active):
		// An Owner is never the directory's to remove: SCIM needs only the
		// settings permission, so an Admin's token could otherwise do what the
		// role rules refuse an Admin. Owners are changed by Owners, in the product.
		if m.Role == string(authz.Owner) {
			return m, nil, nil, &scimProblem{status: http.StatusConflict, scimType: "mutability", detail: "An Owner cannot be deactivated through SCIM. Another Owner changes their role in the admin app first."}
		}
		after, err := q.SetMembershipStatus(ctx, store.SetMembershipStatusParams{Status: string(api.Deactivated), OrgID: m.OrgID, ID: m.ID})
		return after, &statusChange{m.Status, after.Status}, nil, err
	}
	return m, nil, nil, nil
}

// afterStatus is what a status change sets off once committed: the audit
// entry, and at a deactivation the person's sessions and connections
// ending.
func (s *Server) afterStatus(ctx context.Context, m store.Membership, change *statusChange, why string) error {
	if change == nil {
		return nil
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: m.OrgID.String(), Action: "membership.status_changed", TargetType: "membership", TargetID: m.ID.String(),
		Details: map[string]any{"user_id": m.UserID.String(), "from": change.from, "to": change.to, "by": why},
	}); err != nil {
		return err
	}
	if change.to != string(api.Active) {
		s.membershipEnded(ctx, m.OrgID, m.ID, m.UserID, change.to)
	}
	return nil
}

// capRefused is the plan's refusal as a provider shows it, with the admins
// told.
func (s *Server) capRefused(ctx context.Context, org uuid.UUID, r *plan.Refusal) error {
	s.notifyAdmins(ctx, org, "scim-cap:"+time.Now().UTC().Format("2006-01-02"), "scim_cap_reached", map[string]any{
		"message": r.Message, "heading": "Directory sync hit the user limit", "line": r.Message,
	})
	return &scimProblem{status: http.StatusForbidden, detail: r.Message}
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	p := store.ListScimMembershipsParams{OrgID: org}
	if f := strings.TrimSpace(r.URL.Query().Get("filter")); f != "" {
		conds, err := parseFilter(f)
		if err != nil {
			return badRequest("invalidFilter", err.Error())
		}
		for _, c := range conds {
			v := str(c.value)
			switch {
			case c.path == "username":
				p.UserName = text(&v)
			case c.path == "externalid":
				p.ExternalID = text(&v)
			case c.path == "id":
				id, err := uuid.Parse(v)
				if err != nil {
					writeSCIM(w, http.StatusOK, listResponse(nil, 0, 1))
					return nil
				}
				p.ID = pgtype.UUID{Bytes: id, Valid: true}
			case strings.HasPrefix(c.path, "emails") && strings.HasSuffix(c.path, ".value"):
				p.Email = text(&v)
			default:
				return badRequest("invalidFilter", "Filtering users on "+c.path+" is not supported; use userName, externalId, id or emails.")
			}
		}
	}
	start, count := scimPage(r)
	p.Skip, p.PageSize = int32(start-1), int32(count)
	var (
		total int64
		rows  []store.ListScimMembershipsRow
	)
	err := s.cluster.Read(r.Context(), org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if total, err = q.CountScimMemberships(r.Context(), store.CountScimMembershipsParams{
			OrgID: org, ID: p.ID, UserName: p.UserName, Email: p.Email, ExternalID: p.ExternalID,
		}); err != nil {
			return err
		}
		rows, err = q.ListScimMemberships(r.Context(), p)
		return err
	})
	if err != nil {
		return err
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.userResource(row.Membership, row.User))
	}
	writeSCIM(w, http.StatusOK, listResponse(out, int(total), start))
	return nil
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	row, err := s.scimUser(r.Context(), org, r.PathValue("id"))
	if err != nil {
		return err
	}
	writeSCIM(w, http.StatusOK, s.userResource(row.Membership, row.User))
	return nil
}

var errNoUser = &scimProblem{status: http.StatusNotFound, detail: "No such user."}

func (s *Server) scimUser(ctx context.Context, org uuid.UUID, rawID string) (store.ScimMembershipRow, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return store.ScimMembershipRow{}, errNoUser
	}
	var row store.ScimMembershipRow
	err = s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).ScimMembership(ctx, store.ScimMembershipParams{OrgID: org, ID: id})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return row, errNoUser
	}
	return row, err
}

// scimCreateUser is a person the provider assigned to the product: a
// membership with the User role, or, for an address that already has an
// account, a membership added to it. Sign-in is still through the org's
// identity provider.
func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	ctx := r.Context()
	res, problem := readResource(r)
	if problem != nil {
		return problem
	}
	f := userFieldsOf(res)
	if f.userName == "" {
		return badRequest("invalidValue", "userName is required.")
	}
	if f.email == "" {
		return badRequest("invalidValue", "An email address is required, in emails or as the userName.")
	}
	active := f.active == nil || *f.active
	name := f.name
	if name == "" || len(name) > 200 {
		name = localPart(f.email)
	}
	var (
		m       store.Membership
		user    store.User
		created bool
		change  *statusChange
		refusal *plan.Refusal
	)
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if f.externalID != "" {
			if _, err := q.MembershipByExternalID(ctx, store.MembershipByExternalIDParams{OrgID: org, ExternalID: pgtype.Text{String: f.externalID, Valid: true}}); err == nil {
				return &scimProblem{status: http.StatusConflict, scimType: "uniqueness", detail: "A user with this externalId exists."}
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var err error
		if user, _, err = findOrCreateUser(ctx, q, f.email, name); err != nil {
			return err
		}
		row, err := q.GetMembershipByUser(ctx, store.GetMembershipByUserParams{OrgID: org, UserID: user.ID})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if active {
				if refusal, err = s.admit(ctx, q, org, string(api.Member)); err != nil {
					return err
				}
				if refusal != nil {
					return errRefusedByPlan
				}
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			if m, err = q.InsertMembership(ctx, store.InsertMembershipParams{
				OrgID: org, ID: id, UserID: user.ID, Kind: string(api.Member), Role: string(authz.User), Source: "scim", Attributes: []byte("{}"),
			}); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		case row.Membership.Kind != string(api.Member):
			return &scimProblem{status: http.StatusConflict, scimType: "uniqueness", detail: "This address belongs to a guest of the organization."}
		case row.Membership.ExternalID.Valid:
			return &scimProblem{status: http.StatusConflict, scimType: "uniqueness", detail: "A user with this userName exists."}
		case row.Membership.Status == statusLeft:
			if active {
				if refusal, err = s.admit(ctx, q, org, string(api.Member)); err != nil {
					return err
				}
				if refusal != nil {
					return errRefusedByPlan
				}
			}
			if m, err = q.RejoinMembership(ctx, store.RejoinMembershipParams{Role: string(authz.User), Kind: string(api.Member), Source: "scim", OrgID: org, ID: row.Membership.ID}); err != nil {
				return err
			}
			created = true
		default:
			// Known already, by invite or sign-in: the provider takes it over.
			m = row.Membership
		}
		if m, err = saveUser(ctx, q, m, res, true); err != nil {
			return err
		}
		m, change, refusal, err = s.setActive(ctx, q, m, active)
		if refusal != nil {
			return errRefusedByPlan
		}
		return err
	})
	if errors.Is(err, errRefusedByPlan) {
		s.scimLog(ctx, org, "create user", nil, nil, "failed", refusal.Message, map[string]any{"reason": "user_cap"})
		return s.capRefused(ctx, org, refusal)
	}
	if err != nil {
		var p *scimProblem
		if errors.As(err, &p) {
			s.scimLog(ctx, org, "create user", nil, nil, "failed", p.detail, nil)
		}
		return err
	}
	if created {
		if err := s.recordCreated(ctx, m); err != nil {
			return err
		}
	} else if err := s.recorder.Record(ctx, audit.Event{
		OrgID: org.String(), Action: "scim.user.linked", TargetType: "membership", TargetID: m.ID.String(),
		Details: map[string]any{"user_id": m.UserID.String()},
	}); err != nil {
		return err
	}
	if change != nil && created {
		// Created inactive: nobody was signed in to be told.
		change = nil
	}
	if err := s.afterStatus(ctx, m, change, "scim"); err != nil {
		return err
	}
	operation := "create user"
	if !created {
		operation = "link user"
	}
	s.scimLog(ctx, org, operation, &m.ID, nil, "ok", "", map[string]any{"active": m.Status == string(api.Active)})
	w.Header().Set("Location", s.scimBase(org)+"/Users/"+m.ID.String())
	writeSCIM(w, http.StatusCreated, s.userResource(m, user))
	return nil
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	res, problem := readResource(r)
	if problem != nil {
		return problem
	}
	_, said := key(res, "active")
	return s.scimUpdateUser(w, r, org, "replace user", said, func(map[string]any) (map[string]any, error) { return res, nil })
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	ops, problem := readPatch(r)
	if problem != nil {
		return problem
	}
	return s.scimUpdateUser(w, r, org, "update user", mentions(ops, "active"), func(res map[string]any) (map[string]any, error) {
		return res, applyPatch(res, ops)
	})
}

// scimUpdateUser changes one person as the provider says: directory
// attributes in place, active as said, and never the person's own profile.
func (s *Server) scimUpdateUser(w http.ResponseWriter, r *http.Request, org uuid.UUID, operation string, activeSaid bool, change func(map[string]any) (map[string]any, error)) error {
	ctx := r.Context()
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return errNoUser
	}
	var (
		m       store.Membership
		user    store.User
		moved   *statusChange
		refusal *plan.Refusal
	)
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		row, err := q.ScimMembership(ctx, store.ScimMembershipParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoUser
		}
		if err != nil {
			return err
		}
		user = row.User
		res, err := change(s.userResource(row.Membership, row.User))
		if err != nil {
			return err
		}
		f := userFieldsOf(res)
		if f.userName == "" {
			return badRequest("invalidValue", "userName is required.")
		}
		if f.externalID != "" && f.externalID != row.Membership.ExternalID.String {
			if other, err := q.MembershipByExternalID(ctx, store.MembershipByExternalIDParams{OrgID: org, ExternalID: pgtype.Text{String: f.externalID, Valid: true}}); err == nil && other.Membership.ID != id {
				return &scimProblem{status: http.StatusConflict, scimType: "uniqueness", detail: "Another user has this externalId."}
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if m, err = saveUser(ctx, q, row.Membership, res, activeSaid); err != nil {
			return err
		}
		if activeSaid && f.active != nil {
			m, moved, refusal, err = s.setActive(ctx, q, m, *f.active)
			if refusal != nil {
				return errRefusedByPlan
			}
		}
		return err
	})
	if errors.Is(err, errRefusedByPlan) {
		s.scimLog(ctx, org, operation, &id, nil, "failed", refusal.Message, map[string]any{"reason": "user_cap"})
		return s.capRefused(ctx, org, refusal)
	}
	if err != nil {
		var p *scimProblem
		if errors.As(err, &p) && p.status != http.StatusNotFound {
			s.scimLog(ctx, org, operation, &id, nil, "failed", p.detail, nil)
		}
		return err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: org.String(), Action: "scim.user.updated", TargetType: "membership", TargetID: m.ID.String(),
		Details: map[string]any{"user_id": m.UserID.String()},
	}); err != nil {
		return err
	}
	if err := s.afterStatus(ctx, m, moved, "scim"); err != nil {
		return err
	}
	details := map[string]any{}
	if moved != nil {
		details["from"], details["to"] = moved.from, moved.to
		operation = map[string]string{string(api.Active): "reactivate user", string(api.Deactivated): "deactivate user"}[moved.to]
	}
	s.scimLog(ctx, org, operation, &m.ID, nil, "ok", "", details)
	writeSCIM(w, http.StatusOK, s.userResource(m, user))
	return nil
}

// scimDeleteUser is a deactivation. SCIM never deletes data; the membership
// stays, deactivated, and is no longer the provider's.
func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request, org uuid.UUID) error {
	ctx := r.Context()
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return errNoUser
	}
	var (
		m     store.Membership
		moved *statusChange
	)
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		row, err := q.ScimMembership(ctx, store.ScimMembershipParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoUser
		}
		if err != nil {
			return err
		}
		if m, moved, _, err = s.setActive(ctx, q, row.Membership, false); err != nil {
			return err
		}
		return q.ForgetScimMembership(ctx, store.ForgetScimMembershipParams{OrgID: org, ID: id})
	})
	if err != nil {
		var p *scimProblem
		if errors.As(err, &p) && p.status != http.StatusNotFound {
			s.scimLog(ctx, org, "delete user", &id, nil, "failed", p.detail, nil)
		}
		return err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: org.String(), Action: "scim.user.deleted", TargetType: "membership", TargetID: id.String(),
		Details: map[string]any{"user_id": m.UserID.String(), "kept": true},
	}); err != nil {
		return err
	}
	if err := s.afterStatus(ctx, m, moved, "scim"); err != nil {
		return err
	}
	s.scimLog(ctx, org, "delete user", &id, nil, "ok", "", map[string]any{"deactivated": true})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// WithSCIMTokenPrefix is s minting SCIM tokens that start with prefix
// (config.SCIMTokenPrefixFrom); config.DefaultSCIMTokenPrefix otherwise.
func (s *Server) WithSCIMTokenPrefix(prefix string) *Server {
	s.scimPrefix = prefix
	return s
}

// scimTokenPrefix is what every SCIM token this service mints starts with.
func (s *Server) scimTokenPrefix() string {
	if s.scimPrefix == "" {
		return config.DefaultSCIMTokenPrefix
	}
	return s.scimPrefix
}
