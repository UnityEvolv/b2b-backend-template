package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// API keys and personal access tokens (docs/api-keys.md).
//
// A token is the kind's prefix and 32 random bytes; only its SHA-256 is
// kept. Every request that brings one, to any service, is resolved here at
// that moment: found by its hash, refused when revoked or expired, counted
// against the key's rate limit, checked against the org's plan, and its
// first use audited. What it may do is then the permission check every
// request makes (pkg/authz.Require), with the key's groups.

// lastUsedEvery is how stale last_used_at may be: it is written at most
// once in this, so a busy key costs no write per request.
const lastUsedEvery = time.Minute

// WithPlans is s checking API access against plans, at the moment a key
// is made and every time one is used. Without it, API access is refused.
func (s *Server) WithPlans(plans plan.Source) *Server {
	s.plans = plans
	return s
}

// keyPrefixes is what tokens this service mints start with.
func (s *Server) keyPrefixes() config.KeyPrefixes {
	if s.cfg.KeyPrefixes.Org == "" || s.cfg.KeyPrefixes.Personal == "" {
		return config.DefaultKeyPrefixes
	}
	return s.cfg.KeyPrefixes
}

// grantable is whether a key may be granted group g: a group of the
// org's configuration, never the Admin's settings, an Owner-only action,
// or api_keys itself, so a key never makes or revokes keys.
func grantable(g authz.Permission) bool {
	return g != authz.Settings && g != authz.APIKeys && !slices.Contains(authz.OwnerOnly, g)
}

// checkGroups is the request's groups, deduplicated, when every one is
// grantable and held by grant; otherwise the fields to refuse with.
func checkGroups(in []string, grant authz.Grant) ([]string, map[string]string) {
	var out []string
	for _, g := range in {
		g = strings.TrimSpace(g)
		if slices.Contains(out, g) {
			continue
		}
		if g == "" || !grantable(authz.Permission(g)) || !grant.Has(authz.Permission(g)) {
			return nil, map[string]string{"groups": "permission groups you hold yourself; never " + string(authz.APIKeys) + ", " + string(authz.Settings) + " or an Owner-only action"}
		}
		out = append(out, g)
	}
	if len(out) == 0 {
		return nil, map[string]string{"groups": "at least one permission group"}
	}
	return out, nil
}

// apiAccess is nil when org's plan includes API access now, or the
// refusal.
func (s *Server) apiAccess(ctx context.Context, org uuid.UUID) (*plan.Refusal, error) {
	if s.plans == nil {
		return &plan.Refusal{Limit: string(plan.APIAccess), Message: "API access is not available."}, nil
	}
	e, err := s.plans.Entitlements(ctx, org.String())
	if err != nil {
		return nil, err
	}
	if r, ok := plan.AsRefusal(e.CheckFeature(plan.APIAccess)); ok {
		return r, nil
	}
	return nil, nil
}

func planError(r *plan.Refusal) api.Error {
	fields := r.Fields()
	return api.Error{Code: plan.Code, Message: r.Message, Fields: &fields}
}

func toAPIKey(k store.ApiKey) api.ApiKey {
	out := api.ApiKey{
		Id: k.ID, OrgId: k.OrgID, Kind: api.ApiKeyKind(k.Kind), Name: k.Name, Prefix: k.Prefix, Groups: k.Groups,
		CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt.UTC(),
		ExpiresAt: timeOf(k.ExpiresAt), LastUsedAt: timeOf(k.LastUsedAt), RevokedAt: timeOf(k.RevokedAt),
		UserId: uuidOf(k.UserID), MembershipId: uuidOf(k.MembershipID),
	}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	return out
}

// newKey is the input checked: a name, an end in the future if any.
func newKey(in *api.NewApiKey) (name string, ends pgtype.Timestamptz, fields map[string]string) {
	if in == nil {
		return "", ends, map[string]string{"name": "1 to 100 characters", "groups": "at least one permission group"}
	}
	name = strings.TrimSpace(in.Name)
	fields = map[string]string{}
	if name == "" || len([]rune(name)) > 100 {
		fields["name"] = "1 to 100 characters"
	}
	if in.ExpiresAt != nil {
		if !in.ExpiresAt.After(time.Now()) {
			fields["expires_at"] = "a time in the future, or none"
		}
		ends = pgtype.Timestamptz{Time: in.ExpiresAt.UTC(), Valid: true}
	}
	if len(fields) == 0 {
		fields = nil
	}
	return name, ends, fields
}

// mint makes a key: its token, shown once, and its row. Audited.
func (s *Server) mint(ctx context.Context, params store.InsertAPIKeyParams) (api.ApiKeyCreated, error) {
	prefix := s.keyPrefixes().Org
	if params.Kind == auth.PersonalKey {
		prefix = s.keyPrefixes().Personal
	}
	secret, _, err := newSecret()
	if err != nil {
		return api.ApiKeyCreated{}, err
	}
	raw := prefix + secret
	id, err := uuid.NewV7()
	if err != nil {
		return api.ApiKeyCreated{}, err
	}
	params.ID, params.Prefix, params.TokenHash = id, raw[:len(prefix)+6], hashSecret(raw)
	var row store.ApiKey
	err = s.cluster.Tx(ctx, params.OrgID.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).InsertAPIKey(ctx, params)
		return err
	})
	if err != nil {
		return api.ApiKeyCreated{}, err
	}
	details := map[string]any{"kind": row.Kind, "prefix": row.Prefix, "groups": row.Groups}
	if row.ExpiresAt.Valid {
		details["expires_at"] = row.ExpiresAt.Time.UTC().Format(time.RFC3339)
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: row.OrgID.String(), Action: "api_key.created", TargetType: "api_key", TargetID: row.ID.String(), Details: details}); err != nil {
		return api.ApiKeyCreated{}, err
	}
	return api.ApiKeyCreated{Key: toAPIKey(row), Token: raw}, nil
}

// noKeys refuses a request made with a key: keys never make, list or
// revoke keys.
func noKeys(ctx context.Context) bool {
	_, ok := auth.KeyFrom(ctx)
	return ok
}

const keysOnlyBySession = "API keys and personal access tokens are managed when signed in, not with a key."

// noKeysWhileImpersonating refuses a support session a key: a credential
// that outlived the impersonation would outlive the consent.
const noKeysWhileImpersonating = "A support session cannot make API keys or personal access tokens."

// CreateApiKey makes an org's key, granted groups the caller holds.
func (s *Server) CreateApiKey(ctx context.Context, req api.CreateApiKeyRequestObject) (api.CreateApiKeyResponseObject, error) {
	if auth.Impersonating(ctx) {
		return api.CreateApiKey403JSONResponse{Code: codeImpersonating, Message: noKeysWhileImpersonating}, nil
	}
	if noKeys(ctx) {
		return api.CreateApiKey403JSONResponse{Code: httpx.CodeForbidden, Message: keysOnlyBySession}, nil
	}
	grant, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.APIKeys)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return api.CreateApiKey401JSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}, nil
		}
		return api.CreateApiKey403JSONResponse{Code: authz.Code, Message: "You do not have permission to do this."}, nil
	}
	if strings.EqualFold(req.OrgId.String(), auth.PlatformOrg) {
		return api.CreateApiKey403JSONResponse{Code: httpx.CodeForbidden, Message: "The platform organization has no API keys."}, nil
	}
	name, ends, fields := newKey(req.Body)
	var groups []string
	if req.Body != nil {
		var bad map[string]string
		if groups, bad = checkGroups(req.Body.Groups, grant); bad != nil {
			fields = mergeFields(fields, bad)
		}
	}
	if fields != nil {
		return api.CreateApiKey400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	if r, err := s.apiAccess(ctx, req.OrgId); err != nil || r != nil {
		if err != nil {
			return nil, err
		}
		return api.CreateApiKey403JSONResponse(planError(r)), nil
	}
	out, err := s.mint(ctx, store.InsertAPIKeyParams{OrgID: req.OrgId, Kind: auth.OrgKey, Name: name, Groups: groups, ExpiresAt: ends})
	if err != nil {
		return nil, err
	}
	return api.CreateApiKey201JSONResponse(out), nil
}

// ListApiKeys is every key and personal access token in the org.
func (s *Server) ListApiKeys(ctx context.Context, req api.ListApiKeysRequestObject) (api.ListApiKeysResponseObject, error) {
	if noKeys(ctx) {
		return api.ListApiKeys403JSONResponse{Code: httpx.CodeForbidden, Message: keysOnlyBySession}, nil
	}
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.APIKeys); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return api.ListApiKeys401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.ListApiKeys403JSONResponse{Code: authz.Code, Message: "You do not have permission to do this."}, nil
	}
	var rows []store.ApiKey
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListAPIKeysOfOrg(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ApiKeyList{Keys: make([]api.ApiKey, 0, len(rows))}
	for _, r := range rows {
		out.Keys = append(out.Keys, toAPIKey(r))
	}
	return api.ListApiKeys200JSONResponse(out), nil
}

// RevokeApiKey revokes any key or personal access token in the org.
func (s *Server) RevokeApiKey(ctx context.Context, req api.RevokeApiKeyRequestObject) (api.RevokeApiKeyResponseObject, error) {
	if noKeys(ctx) {
		return api.RevokeApiKey403JSONResponse{Code: httpx.CodeForbidden, Message: keysOnlyBySession}, nil
	}
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.APIKeys); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return api.RevokeApiKey401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.RevokeApiKey403JSONResponse{Code: authz.Code, Message: "You do not have permission to do this."}, nil
	}
	ok, err := s.revokeKey(ctx, req.OrgId, req.KeyId, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.RevokeApiKey404JSONResponse{Code: "api_key.not_found", Message: "No such key, or it is already revoked."}, nil
	}
	return api.RevokeApiKey204Response{}, nil
}

// revokeKey revokes one key, when it is mine's (if mine is set) and not
// already revoked. Audited.
func (s *Server) revokeKey(ctx context.Context, org, id uuid.UUID, mine *uuid.UUID) (bool, error) {
	var row store.ApiKey
	found := false
	err := s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		k, err := q.GetAPIKey(ctx, store.GetAPIKeyParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if mine != nil && (!k.MembershipID.Valid || uuid.UUID(k.MembershipID.Bytes) != *mine) {
			return nil
		}
		row, err = q.RevokeAPIKey(ctx, store.RevokeAPIKeyParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil || !found {
		return false, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "api_key.revoked", TargetType: "api_key", TargetID: id.String(),
		Details: map[string]any{"kind": row.Kind, "prefix": row.Prefix}}); err != nil {
		return false, err
	}
	return true, nil
}

// member is the person signed in to org, by a session's access token: not
// a key, not a service, not a platform operator looking in.
func member(ctx context.Context, org uuid.UUID) (auth.Caller, uuid.UUID, uuid.UUID, bool) {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.IsService() || auth.RequireOrg(ctx, org.String()) != nil || strings.EqualFold(c.OrgID, auth.PlatformOrg) {
		return auth.Caller{}, uuid.Nil, uuid.Nil, false
	}
	user, err1 := uuid.Parse(c.UserID)
	membership, err2 := uuid.Parse(c.MembershipID)
	return c, user, membership, err1 == nil && err2 == nil
}

// CreatePersonalAccessToken makes the caller's own token in the org,
// granted groups they hold now.
func (s *Server) CreatePersonalAccessToken(ctx context.Context, req api.CreatePersonalAccessTokenRequestObject) (api.CreatePersonalAccessTokenResponseObject, error) {
	if auth.Impersonating(ctx) {
		return api.CreatePersonalAccessToken403JSONResponse{Code: codeImpersonating, Message: noKeysWhileImpersonating}, nil
	}
	_, user, membership, ok := member(ctx, req.OrgId)
	if !ok {
		return api.CreatePersonalAccessToken403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a member signed in to the organization makes their own token."}, nil
	}
	grant, err := s.authz.Grant(ctx, req.OrgId.String(), membership.String())
	if err != nil {
		if errors.Is(err, authz.ErrNoMembership) {
			return api.CreatePersonalAccessToken403JSONResponse{Code: authz.Code, Message: "You are not an active member of this organization."}, nil
		}
		return nil, err
	}
	name, ends, fields := newKey(req.Body)
	var groups []string
	if req.Body != nil {
		var bad map[string]string
		if groups, bad = checkGroups(req.Body.Groups, grant); bad != nil {
			fields = mergeFields(fields, bad)
		}
	}
	if fields != nil {
		return api.CreatePersonalAccessToken400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	if r, err := s.apiAccess(ctx, req.OrgId); err != nil || r != nil {
		if err != nil {
			return nil, err
		}
		return api.CreatePersonalAccessToken403JSONResponse(planError(r)), nil
	}
	out, err := s.mint(ctx, store.InsertAPIKeyParams{OrgID: req.OrgId, Kind: auth.PersonalKey, Name: name, Groups: groups, ExpiresAt: ends,
		UserID: pgtype.UUID{Bytes: user, Valid: true}, MembershipID: pgtype.UUID{Bytes: membership, Valid: true}})
	if err != nil {
		return nil, err
	}
	return api.CreatePersonalAccessToken201JSONResponse(out), nil
}

// ListPersonalAccessTokens is the caller's own tokens in the org.
func (s *Server) ListPersonalAccessTokens(ctx context.Context, req api.ListPersonalAccessTokensRequestObject) (api.ListPersonalAccessTokensResponseObject, error) {
	_, _, membership, ok := member(ctx, req.OrgId)
	if !ok {
		return api.ListPersonalAccessTokens403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a member signed in to the organization lists their own tokens."}, nil
	}
	var rows []store.ApiKey
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListPersonalTokens(ctx, store.ListPersonalTokensParams{OrgID: req.OrgId, MembershipID: pgtype.UUID{Bytes: membership, Valid: true}})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ApiKeyList{Keys: make([]api.ApiKey, 0, len(rows))}
	for _, r := range rows {
		out.Keys = append(out.Keys, toAPIKey(r))
	}
	return api.ListPersonalAccessTokens200JSONResponse(out), nil
}

// RevokePersonalAccessToken revokes one of the caller's own tokens.
func (s *Server) RevokePersonalAccessToken(ctx context.Context, req api.RevokePersonalAccessTokenRequestObject) (api.RevokePersonalAccessTokenResponseObject, error) {
	_, _, membership, ok := member(ctx, req.OrgId)
	if !ok {
		return api.RevokePersonalAccessToken403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a member signed in to the organization revokes their own tokens."}, nil
	}
	found, err := s.revokeKey(ctx, req.OrgId, req.KeyId, &membership)
	if err != nil {
		return nil, err
	}
	if !found {
		return api.RevokePersonalAccessToken404JSONResponse{Code: "api_key.not_found", Message: "No such token of yours, or it is already revoked."}, nil
	}
	return api.RevokePersonalAccessToken204Response{}, nil
}

// ResolveApiKey is another service's auth middleware asking what a key is.
func (s *Server) ResolveApiKey(ctx context.Context, req api.ResolveApiKeyRequestObject) (api.ResolveApiKeyResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.ResolveApiKey403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	if req.Body == nil {
		return api.ResolveApiKey401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in to continue."}}, nil
	}
	k, err := s.Resolve(ctx, req.Body.Token)
	var refusal *auth.KeyRefusal
	switch {
	case err == nil:
		out := api.ResolvedApiKey{Id: uuid.MustParse(k.ID), Kind: api.ResolvedApiKeyKind(k.Kind), OrgId: uuid.MustParse(k.OrgID), Groups: k.Groups}
		if k.Kind == auth.PersonalKey {
			user, membership := uuid.MustParse(k.UserID), uuid.MustParse(k.MembershipID)
			out.UserId, out.MembershipId = &user, &membership
		}
		return api.ResolveApiKey200JSONResponse(out), nil
	case errors.Is(err, auth.ErrUnauthenticated):
		return api.ResolveApiKey401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in to continue."}}, nil
	case errors.As(err, &refusal) && refusal.Status == 429:
		retry := refusal.RetryAfter
		return api.ResolveApiKey429JSONResponse{Body: api.Error{Code: refusal.Body.Code, Message: refusal.Body.Message}, Headers: api.ResolveApiKey429ResponseHeaders{RetryAfter: &retry}}, nil
	case errors.As(err, &refusal):
		body := api.Error{Code: refusal.Body.Code, Message: refusal.Body.Message}
		if refusal.Body.Fields != nil {
			body.Fields = &refusal.Body.Fields
		}
		return api.ResolveApiKey403JSONResponse(body), nil
	}
	return nil, err
}

// Resolve is what raw is, now: auth.KeyResolver, for this service's own
// middleware and, through ResolveApiKey, every other service's.
func (s *Server) Resolve(ctx context.Context, raw string) (auth.Key, error) {
	if len(raw) > 200 || !auth.IsKeyToken(raw) {
		return auth.Key{}, auth.ErrUnauthenticated
	}
	hash := hashSecret(raw)
	var k store.ApiKey
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		k, err = store.New(tx).APIKeyByHash(ctx, hash)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Key{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return auth.Key{}, err
	}
	now := time.Now()
	if subtle.ConstantTimeCompare(k.TokenHash, hash) != 1 || k.RevokedAt.Valid || (k.ExpiresAt.Valid && !now.Before(k.ExpiresAt.Time)) {
		return auth.Key{}, auth.ErrUnauthenticated
	}
	key := auth.Key{ID: k.ID.String(), Kind: k.Kind, OrgID: k.OrgID.String(), Groups: k.Groups}
	if k.MembershipID.Valid {
		key.UserID, key.MembershipID = uuid.UUID(k.UserID.Bytes).String(), uuid.UUID(k.MembershipID.Bytes).String()
	}
	// One allowance per key, wherever it is used.
	if s.limiter != nil {
		v, err := s.limiter.Take(ctx, ratelimit.APIKey, "key:"+key.ID)
		if err != nil {
			return auth.Key{}, err
		}
		if !v.Allowed {
			return auth.Key{}, &auth.KeyRefusal{Status: 429, RetryAfter: int(math.Max(1, math.Ceil(v.RetryAfter.Seconds()))),
				Body: httpx.Error{Code: httpx.CodeRateLimited, Message: "Too many requests with this key. Try again shortly."}}
		}
	}
	if r, err := s.apiAccess(ctx, k.OrgID); err != nil || r != nil {
		if err != nil {
			return auth.Key{}, err
		}
		return auth.Key{}, &auth.KeyRefusal{Status: 403, Body: httpx.Error{Code: plan.Code, Message: r.Message, Fields: r.Fields()}}
	}
	if err := s.used(ctx, key, k.OrgID, now); err != nil {
		return auth.Key{}, err
	}
	return key, nil
}

// used records a use: the first one audited, then the last one at most once
// a minute.
func (s *Server) used(ctx context.Context, key auth.Key, org uuid.UUID, now time.Time) error {
	id := uuid.MustParse(key.ID)
	at := pgtype.Timestamptz{Time: now, Valid: true}
	var first int64
	err := s.cluster.Tx(db.WithActor(ctx, key.Actor()), org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if first, err = q.MarkAPIKeyFirstUse(ctx, store.MarkAPIKeyFirstUseParams{Now: at, OrgID: org, ID: id}); err != nil || first > 0 {
			return err
		}
		_, err = q.TouchAPIKey(ctx, store.TouchAPIKeyParams{Now: at, OrgID: org, ID: id, Since: pgtype.Timestamptz{Time: now.Add(-lastUsedEvery), Valid: true}})
		return err
	})
	if err != nil || first == 0 {
		return err
	}
	return s.recorder.Record(ctx, audit.Event{OrgID: org.String(), Action: "api_key.first_used", TargetType: "api_key", TargetID: key.ID,
		Details: map[string]any{"kind": key.Kind}, Actor: key.Actor()})
}

func mergeFields(a, b map[string]string) map[string]string {
	if a == nil {
		a = map[string]string{}
	}
	for k, v := range b {
		a[k] = v
	}
	return a
}
