package server

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/timezone"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

const (
	defaultPage = 50
	maxPage     = 200

	codeDomainTaken = "organization.domain_taken"
	codeKeyReused   = "request.idempotency_key_reused"
)

// bandList is the plan bands for a message: "free, team, ...".
func bandList() string {
	bands := plan.Bands()
	names := make([]string, 0, len(bands))
	for _, b := range bands {
		names = append(names, string(b))
	}
	return strings.Join(names, ", ")
}

// domainShape is a registrable hostname: lower-case labels, at least one dot,
// an alphabetic top level. The email domain an org claims, never a URL.
var domainShape = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// normalizeDomain is the stored form of a domain, or "" when it is not one.
func normalizeDomain(s string) string {
	d := strings.ToLower(strings.TrimSpace(s))
	if !domainShape.MatchString(d) {
		return ""
	}
	return d
}

func toAPI(o store.Organization) api.Organization {
	out := api.Organization{
		OrgId: o.OrgID, Name: o.Name, Plan: api.Plan(o.Plan), TimeZone: o.TimeZone,
		Status: api.OrganizationStatus(o.Status), CreatedAt: o.CreatedAt, LastModifiedAt: o.LastModifiedAt,
	}
	// The cap as the plan table says it now; read at the moment of asking.
	if c := plan.For(plan.Band(o.Plan)).Cap(plan.Users); c != plan.Unlimited {
		out.UserCap = &c
	}
	if o.SuspendedAt.Valid {
		at := o.SuspendedAt.Time
		out.SuspendedAt = &at
	}
	if o.SuspensionReason.Valid {
		out.SuspensionReason = &o.SuspensionReason.String
	}
	if o.ClosingAt.Valid {
		out.ClosingAt = &o.ClosingAt.Time
	}
	if o.PurgeAfter.Valid {
		out.PurgeAfter = &o.PurgeAfter.Time
	}
	if o.DisplayName.Valid {
		out.DisplayName = &o.DisplayName.String
	}
	if o.Domain.Valid {
		out.Domain = &o.Domain.String
	}
	if o.OwnerUserID.Valid {
		id := uuid.UUID(o.OwnerUserID.Bytes)
		out.OwnerUserId = &id
	}
	return out
}

func text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func invalid(message string, fields map[string]string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: message, Fields: &fields}
}

// isUniqueViolation reports whether err is Postgres refusing a duplicate on
// the named index: two requests racing for one domain.
func isUniqueViolation(err error, index string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == index
}

// CreateOrganization makes the tenant, on the free plan, with its first data
// key, in one transaction. Platform operators only until self-serve signup.
//
// The idempotency key is the client's: a retry with the same key finds the
// org the first request made and returns it as if it had just been created.
// The same key with a different request is refused, so a client bug cannot
// silently get the wrong org back.
func (s *Server) CreateOrganization(ctx context.Context, req api.CreateOrganizationRequestObject) (api.CreateOrganizationResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.CreateOrganization403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may create an organization."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 200 {
		fields["name"] = "1 to 200 characters"
	}
	if err := timezone.Validate(body.TimeZone); err != nil {
		fields["time_zone"] = "an IANA zone name such as Europe/London, not an offset"
	}
	var displayName, domain string
	if body.DisplayName != nil {
		displayName = strings.TrimSpace(*body.DisplayName)
		if displayName == "" || len(displayName) > 200 {
			fields["display_name"] = "1 to 200 characters"
		}
	}
	if body.Domain != nil {
		if domain = normalizeDomain(*body.Domain); domain == "" {
			fields["domain"] = "a domain such as acme.com"
		}
	}
	key := strings.TrimSpace(req.Params.IdempotencyKey)
	if key == "" || len(key) > 200 {
		fields["Idempotency-Key"] = "1 to 200 characters"
	}
	if len(fields) > 0 {
		return api.CreateOrganization400JSONResponse{ErrorJSONResponse: invalid("Some fields are not valid.", fields)}, nil
	}
	actor, _ := db.ActorFrom(ctx)

	orgID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var (
		org      store.Organization
		replayed bool
		conflict api.CreateOrganizationResponseObject
	)
	err = s.cluster.Tx(ctx, orgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		params := store.InsertOrganizationParams{
			OrgID: orgID, Name: name, DisplayName: text(displayName), Domain: text(domain),
			TimeZone: body.TimeZone, IdempotencyKey: text(key), Plan: string(plan.Lowest()),
		}
		if body.OwnerUserId != nil {
			params.OwnerUserID = pgtype.UUID{Bytes: *body.OwnerUserId, Valid: true}
		}
		// A replay: this actor used the key before. Answer with what it made,
		// before any check that the first request has since made true (its
		// domain is now claimed, by the org being asked for).
		byKey := store.OrganizationByIdempotencyKeyParams{CreatedBy: string(actor), IdempotencyKey: text(key)}
		var err error
		org, err = q.OrganizationByIdempotencyKey(ctx, byKey)
		if err == nil {
			replayed = true
			if org.Name != name || org.TimeZone != body.TimeZone || org.Domain.String != domain {
				conflict = api.CreateOrganization409JSONResponse{Code: codeKeyReused, Message: "This idempotency key was already used for a different request."}
			}
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if domain != "" {
			if _, err := q.OrganizationIDByDomain(ctx, text(domain)); err == nil {
				conflict = api.CreateOrganization409JSONResponse{Code: codeDomainTaken, Message: "Another organization has claimed this domain."}
				return nil
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		org, err = q.InsertOrganization(ctx, params)
		if errors.Is(err, pgx.ErrNoRows) {
			// Two retries raced; the other one won. Answer with its org.
			replayed = true
			org, err = q.OrganizationByIdempotencyKey(ctx, byKey)
			return err
		}
		if isUniqueViolation(err, "organizations_by_domain") {
			conflict = api.CreateOrganization409JSONResponse{Code: codeDomainTaken, Message: "Another organization has claimed this domain."}
			return nil
		}
		if err != nil {
			return err
		}
		return s.EnsureDataKey(ctx, tx, orgID)
	})
	if err != nil {
		return nil, err
	}
	if conflict != nil {
		return conflict, nil
	}
	if !replayed {
		err := s.recorder.Record(ctx, audit.Event{
			OrgID: org.OrgID.String(), Action: "organization.created",
			TargetType: "organization", TargetID: org.OrgID.String(),
			Details: map[string]any{"plan": org.Plan, "time_zone": org.TimeZone, "domain": org.Domain.String},
		})
		if err != nil {
			return nil, err
		}
	}
	return api.CreateOrganization201JSONResponse(toAPI(org)), nil
}

// ListOrganizations is one page of every org on the platform, for the
// platform's list page: cursor paginated, sorted stably, filtered by a name
// or domain prefix and by plan.
func (s *Server) ListOrganizations(ctx context.Context, req api.ListOrganizationsRequestObject) (api.ListOrganizationsResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		return api.ListOrganizations403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a platform operator may list organizations."}, nil
	}
	p := req.Params
	// The generated binder reads the enums but does not enforce them.
	fields := map[string]string{}
	if p.Sort != nil && *p.Sort != api.CreatedAt && *p.Sort != api.Name {
		fields["sort"] = "created_at or name"
	}
	if p.Order != nil && *p.Order != api.Asc && *p.Order != api.Desc {
		fields["order"] = "asc or desc"
	}
	if p.Plan != nil {
		if _, err := plan.Parse(string(*p.Plan)); err != nil {
			fields["plan"] = "one of " + bandList()
		}
	}
	if p.Status != nil && !p.Status.Valid() {
		fields["status"] = "active or suspended"
	}
	if len(fields) > 0 {
		return api.ListOrganizations400JSONResponse{ErrorJSONResponse: invalid("Some parameters are not valid.", fields)}, nil
	}
	limit := httpx.PageSize(p.Limit, defaultPage, maxPage)
	byName := p.Sort != nil && *p.Sort == api.Name
	// Newest first, A to Z: the order a person expects of each.
	descending := !byName
	if p.Order != nil {
		descending = *p.Order == api.Desc
	}
	var cursor httpx.Cursor
	if p.Cursor != nil {
		c, ok, err := httpx.DecodeCursor(*p.Cursor)
		if err != nil || (ok && byName != (c.Key != "")) {
			return api.ListOrganizations400JSONResponse{ErrorJSONResponse: invalid("The cursor is not valid.", map[string]string{"cursor": "not a cursor this list issued"})}, nil
		}
		cursor = c
	}
	var plan, q, status pgtype.Text
	if p.Plan != nil {
		plan = text(string(*p.Plan))
	}
	if p.Status != nil {
		status = text(string(*p.Status))
	}
	if p.Q != nil {
		q = text(strings.TrimSpace(*p.Q))
	}

	var rows []store.Organization
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		if byName {
			rows, err = store.New(tx).ListOrganizationsByName(ctx, store.ListOrganizationsByNameParams{
				Plan: plan, Status: status, Q: q, Descending: descending, PageSize: int32(limit + 1),
				AfterName: text(cursor.Key), AfterID: pgtype.UUID{Bytes: cursor.ID, Valid: cursor.Key != ""},
			})
		} else {
			rows, err = store.New(tx).ListOrganizationsByCreated(ctx, store.ListOrganizationsByCreatedParams{
				Plan: plan, Status: status, Q: q, Descending: descending, PageSize: int32(limit + 1),
				AfterAt: pgtype.Timestamptz{Time: cursor.At, Valid: !cursor.At.IsZero()}, AfterID: pgtype.UUID{Bytes: cursor.ID, Valid: !cursor.At.IsZero()},
			})
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	page := api.OrganizationPage{Organizations: make([]api.Organization, 0, len(rows))}
	for i, r := range rows {
		if i == limit {
			// One more than asked for was fetched: there is another page.
			last := rows[i-1]
			next := httpx.Cursor{ID: last.OrgID}
			if byName {
				next.Key = strings.ToLower(last.Name)
			} else {
				next.At = last.CreatedAt
			}
			encoded := next.Encode()
			page.NextCursor = &encoded
			break
		}
		page.Organizations = append(page.Organizations, toAPI(r))
	}
	return api.ListOrganizations200JSONResponse(page), nil
}

// UpdateOrganization changes the settings that were sent: an Owner, an
// Admin (the settings permission), or a platform operator.
func (s *Server) UpdateOrganization(ctx context.Context, req api.UpdateOrganizationRequestObject) (api.UpdateOrganizationResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		return api.UpdateOrganization403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to change the organization settings."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	params := store.UpdateOrganizationParams{OrgID: req.OrgId}
	changed := []string{}
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" || len(name) > 200 {
			fields["name"] = "1 to 200 characters"
		}
		params.Name = text(name)
		changed = append(changed, "name")
	}
	if body.TimeZone != nil {
		if err := timezone.Validate(*body.TimeZone); err != nil {
			fields["time_zone"] = "an IANA zone name such as Europe/London, not an offset"
		}
		params.TimeZone = text(*body.TimeZone)
		changed = append(changed, "time_zone")
	}
	if body.DisplayName.IsSpecified() {
		changed = append(changed, "display_name")
		if body.DisplayName.IsNull() {
			params.ClearDisplayName = true
		} else {
			v, _ := body.DisplayName.Get()
			v = strings.TrimSpace(v)
			if v == "" || len(v) > 200 {
				fields["display_name"] = "1 to 200 characters, or null to clear"
			}
			params.DisplayName = text(v)
		}
	}
	if body.Domain.IsSpecified() {
		changed = append(changed, "domain")
		// A claim must be proven: an org sets its domain through the
		// domain endpoints and a TXT record; an operator may set it directly.
		if !mayEditDomainDirectly(ctx) {
			return api.UpdateOrganization403JSONResponse{Code: codeDomainDirect, Message: "A domain is claimed by verifying it: use the domain settings."}, nil
		}
		if body.Domain.IsNull() {
			params.ClearDomain = true
		} else {
			v, _ := body.Domain.Get()
			if d := normalizeDomain(v); d == "" {
				fields["domain"] = "a domain such as acme.com, or null to clear"
			} else {
				params.Domain = text(d)
			}
		}
	}
	if len(fields) > 0 {
		return api.UpdateOrganization400JSONResponse{ErrorJSONResponse: invalid("Some fields are not valid.", fields)}, nil
	}
	if len(changed) == 0 {
		return api.UpdateOrganization400JSONResponse{ErrorJSONResponse: invalid("Nothing to change.", map[string]string{"body": "send at least one setting"})}, nil
	}

	var (
		org      store.Organization
		notFound bool
		taken    bool
	)
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if params.Domain.Valid {
			owner, err := q.OrganizationIDByDomain(ctx, params.Domain)
			if err == nil && owner != req.OrgId {
				taken = true
				return nil
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var err error
		org, err = q.UpdateOrganization(ctx, params)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			notFound = true
			return nil
		case isUniqueViolation(err, "organizations_by_domain"):
			taken = true
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if notFound {
		return api.UpdateOrganization404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if taken {
		return api.UpdateOrganization409JSONResponse{Code: codeDomainTaken, Message: "Another organization has claimed this domain."}, nil
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: org.OrgID.String(), Action: "organization.updated",
		TargetType: "organization", TargetID: org.OrgID.String(),
		Details: map[string]any{"changed": changed},
	})
	if err != nil {
		return nil, err
	}
	return api.UpdateOrganization200JSONResponse(toAPI(org)), nil
}
