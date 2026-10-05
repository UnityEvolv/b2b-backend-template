package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/saml"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// SAML 2.0 single sign-on: an org's provider may be a SAML identity
// provider (preset saml) instead of an OpenID provider. The service is the
// org's service provider: SP-initiated sign-in only, the AuthnRequest over
// HTTP-Redirect and the response over HTTP-POST to the org's own ACS URL.
// The protocol is in internal/saml; this is the API around it.

const (
	presetSAML = "saml"
	// codeSSORequired refuses a password where the org requires its provider.
	codeSSORequired = "sso.required"
)

// spFor is the org's service provider.
func (s *Server) spFor(org uuid.UUID) saml.SP { return saml.SPFor(s.cfg.PublicURL, org.String()) }

// idpOf is a saved SAML provider as sign-in uses it.
func idpOf(p store.IdentityProvider) (saml.IdP, error) {
	out := saml.IdP{EntityID: p.Issuer, SSOURL: p.SamlSsoUrl.String}
	for _, der := range p.SamlCertificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return saml.IdP{}, fmt.Errorf("saved certificate: %w", err)
		}
		out.Certs = append(out.Certs, c)
	}
	return out, nil
}

func mappingOf(p store.IdentityProvider) saml.Mapping {
	return saml.Mapping{Email: p.EmailClaim, Name: p.NameClaim, GivenName: p.SamlGivenNameAttribute.String, FamilyName: p.SamlFamilyNameAttribute.String}
}

// verified is whether the provider has proven itself: an OpenID provider
// when its settings passed the test, a SAML one when someone signed in
// through it.
func verified(p store.IdentityProvider) bool { return p.Status == "active" && p.VerifiedAt.Valid }

// enforcing is whether single sign-on is required of the org's domain now.
func enforcing(p store.IdentityProvider) bool { return p.SsoEnforced && verified(p) }

func (s *Server) samlServiceProvider(org uuid.UUID) api.SamlServiceProvider {
	sp := s.spFor(org)
	return api.SamlServiceProvider{EntityId: sp.EntityID, AcsUrl: sp.ACSURL, MetadataUrl: sp.EntityID, NameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}
}

// samlOf is the saml part of a saved SAML provider, for the admin page.
func (s *Server) samlOf(p store.IdentityProvider) *api.SamlProvider {
	out := &api.SamlProvider{
		EntityId: p.Issuer, SsoUrl: p.SamlSsoUrl.String, MetadataUrl: textPtr(p.SamlMetadataUrl), Profile: p.SamlProfile.String,
		EmailAttribute: p.EmailClaim, NameAttribute: p.NameClaim,
		GivenNameAttribute: textPtr(p.SamlGivenNameAttribute), FamilyNameAttribute: textPtr(p.SamlFamilyNameAttribute),
		Certificates: []api.SamlCertificate{}, ServiceProvider: s.samlServiceProvider(p.OrgID),
	}
	if p.SamlCertificatesExpireAt.Valid {
		out.CertificatesExpireAt = p.SamlCertificatesExpireAt.Time.UTC()
	}
	for _, der := range p.SamlCertificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		out.Certificates = append(out.Certificates, api.SamlCertificate{
			Subject: c.Subject.String(), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), Sha256: fingerprint(der),
		})
	}
	return out
}

// fingerprint is a certificate's SHA-256, as providers show it.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// samlCandidate is a SAML provider as an admin sent it, checked.
type samlCandidate struct {
	source  saml.Source
	profile string
	mapping saml.Mapping
}

// attributePattern is an attribute name: printable, spaces allowed.
var attributePattern = regexp.MustCompile(`^[\x20-\x7e]{1,300}$`)

// samlCandidateOf checks a SAML request and fills in what it left out. An
// OpenID field is a 400 naming it: nothing is silently dropped.
func (s *Server) samlCandidateOf(ctx context.Context, body api.NewIdentityProvider) (samlCandidate, map[string]string) {
	fields := map[string]string{}
	for name, set := range map[string]bool{
		"issuer": body.Issuer != nil, "tenant_id": body.TenantId != nil, "hosted_domain": body.HostedDomain != nil,
		"client_id": body.ClientId != nil, "client_secret": body.ClientSecret != nil, "scopes": body.Scopes != nil,
		"email_claim": body.EmailClaim != nil, "name_claim": body.NameClaim != nil, "require_email_verified": body.RequireEmailVerified != nil,
	} {
		if set {
			fields[name] = "OpenID Connect only; a SAML provider is described by saml"
		}
	}
	var in api.NewSamlSettings
	if body.Saml != nil {
		in = *body.Saml
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	c := samlCandidate{profile: saml.ProfileGeneric}
	metadataURL, metadataXML := str(in.MetadataUrl), str(in.MetadataXml)
	switch {
	case metadataURL != "" && metadataXML != "":
		fields[saml.FieldMetadataURL] = "the metadata URL or the document, not both"
		fields[saml.FieldMetadataXML] = "the metadata URL or the document, not both"
	case metadataURL != "":
		if len(metadataURL) > 1000 || s.oidc.CheckURL(metadataURL) != nil {
			fields[saml.FieldMetadataURL] = "the metadata's https URL"
		} else if !s.oidc.Local() {
			// The early answer; the dialer refuses again at connect time.
			u, _ := url.Parse(metadataURL)
			if err := egress.CheckHost(ctx, net.DefaultResolver, u.Hostname()); err != nil {
				fields[saml.FieldMetadataURL] = "a public address: the service never fetches inside its own network"
			}
		}
		c.source.URL = metadataURL
	case metadataXML != "":
		if len(metadataXML) > saml.MaxMetadata {
			fields[saml.FieldMetadataXML] = "at most 1 MB"
		}
		c.source.XML = []byte(metadataXML)
	}
	if p := str(in.Profile); p != "" {
		c.profile = p
	}
	profile, ok := saml.ProfileNamed(c.profile)
	if !ok {
		fields["saml.profile"] = "okta, entra, google, jumpcloud, adfs, onelogin or generic"
	}
	attr := func(name string, p *string, fallback string, optional bool) string {
		if p == nil {
			return fallback
		}
		v := strings.TrimSpace(*p)
		if v == "" && optional {
			return ""
		}
		if !attributePattern.MatchString(v) {
			fields[name] = "an attribute name"
		}
		return v
	}
	c.mapping = saml.Mapping{
		Email:      attr("saml.email_attribute", in.EmailAttribute, profile.Mapping.Email, false),
		Name:       attr("saml.name_attribute", in.NameAttribute, profile.Mapping.Name, false),
		GivenName:  attr("saml.given_name_attribute", in.GivenNameAttribute, profile.Mapping.GivenName, true),
		FamilyName: attr("saml.family_name_attribute", in.FamilyNameAttribute, profile.Mapping.FamilyName, true),
	}
	return c, fields
}

// prepareSAML is a SAML request checked and its metadata tested. With no
// metadata sent, the saved provider's is kept, its certificates judged
// again; there must be one. A non-nil fields is a 400.
func (s *Server) prepareSAML(ctx context.Context, orgID uuid.UUID, body api.NewIdentityProvider) (samlCandidate, saml.Tested, map[string]string, error) {
	c, fields := s.samlCandidateOf(ctx, body)
	if len(fields) > 0 {
		return c, saml.Tested{}, fields, nil
	}
	now := time.Now()
	if c.source.URL != "" || c.source.XML != nil {
		return c, saml.Test(ctx, s.oidc.HTTP(), s.oidc.CheckURL, c.source, s.spFor(orgID), now), nil, nil
	}
	var p store.IdentityProvider
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).GetIdentityProvider(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && p.Preset != presetSAML) {
		return c, saml.Tested{}, map[string]string{saml.FieldMetadataURL: "the metadata URL or the document: required the first time"}, nil
	}
	if err != nil {
		return c, saml.Tested{}, nil, err
	}
	idp, err := idpOf(p)
	if err != nil {
		return c, saml.Tested{}, nil, err
	}
	// The saved URL is kept with the saved metadata.
	c.source.URL = p.SamlMetadataUrl.String
	tested, _ := saml.Recheck(idp, now)
	return c, tested, nil, nil
}

func samlReport(t saml.Tested, sp saml.SP) api.IdentityProviderTest {
	out := api.IdentityProviderTest{Ok: t.OK(), RedirectUri: sp.ACSURL, Checks: make([]api.IdentityProviderCheck, 0, len(t.Checks))}
	if t.IdP.EntityID != "" {
		issuer := t.IdP.EntityID
		out.Issuer = &issuer
	}
	for _, c := range t.Checks {
		check := api.IdentityProviderCheck{Check: c.Name, Ok: c.OK, Message: c.Message}
		if c.Field != "" {
			field := c.Field
			check.Field = &field
		}
		out.Checks = append(out.Checks, check)
	}
	return out
}

// failedTest is the 422 for settings that did not pass, logged by the
// check's name only (its message can carry a URL).
func (s *Server) failedTest(orgID uuid.UUID, checks []api.IdentityProviderCheck) api.Error {
	failed := map[string]string{}
	message := "The provider could not be reached with these settings."
	name := ""
	for _, check := range checks {
		if !check.Ok {
			message, name = check.Message, check.Check
			if check.Field != nil {
				failed[*check.Field] = check.Message
			}
		}
	}
	s.logger.Warn("identity provider settings refused", "org_id", orgID, "check", name)
	out := api.Error{Code: "identity_provider.test_failed", Message: message}
	if len(failed) > 0 {
		out.Fields = &failed
	}
	return out
}

// setSAML saves a SAML provider that passed its test.
func (s *Server) setSAML(ctx context.Context, orgID uuid.UUID, body api.NewIdentityProvider) (api.SetIdentityProviderResponseObject, error) {
	c, tested, fields, err := s.prepareSAML(ctx, orgID, body)
	if err != nil {
		return nil, err
	}
	if fields != nil {
		return api.SetIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	report := samlReport(tested, s.spFor(orgID))
	if !tested.OK() {
		return api.SetIdentityProvider422JSONResponse(s.failedTest(orgID, report.Checks)), nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	certs := make([][]byte, 0, len(tested.IdP.Certs))
	for _, cert := range tested.IdP.Certs {
		certs = append(certs, cert.Raw)
	}
	text := func(v string) pgtype.Text { return pgtype.Text{String: v, Valid: v != ""} }
	var p store.IdentityProvider
	err = s.cluster.Tx(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).UpsertSamlIdentityProvider(ctx, store.UpsertSamlIdentityProviderParams{
			OrgID: orgID, ID: id, Issuer: tested.IdP.EntityID, ClientID: s.spFor(orgID).EntityID,
			EmailClaim: c.mapping.Email, NameClaim: c.mapping.Name,
			SamlSsoUrl: text(tested.IdP.SSOURL), SamlCertificates: certs,
			SamlCertificatesExpireAt: pgtype.Timestamptz{Time: tested.ExpiresAt, Valid: true},
			SamlMetadataUrl:          text(c.source.URL), SamlProfile: text(c.profile),
			SamlGivenNameAttribute: text(c.mapping.GivenName), SamlFamilyNameAttribute: text(c.mapping.FamilyName),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	metadata := "kept"
	switch {
	case body.Saml != nil && body.Saml.MetadataXml != nil && strings.TrimSpace(*body.Saml.MetadataXml) != "":
		metadata = "uploaded"
	case body.Saml != nil && body.Saml.MetadataUrl != nil && strings.TrimSpace(*body.Saml.MetadataUrl) != "":
		metadata = "url"
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: orgID.String(), Action: "identity_provider.configured", TargetType: "identity_provider", TargetID: p.ID.String(),
		Details: map[string]any{"preset": presetSAML, "issuer": p.Issuer, "profile": c.profile, "metadata": metadata, "verified": p.VerifiedAt.Valid},
	}); err != nil {
		return nil, err
	}
	return api.SetIdentityProvider200JSONResponse(s.toAPI(p)), nil
}

// startSAML sends the browser to the org's SAML provider with a fresh
// AuthnRequest. The attempt keeps the request's id, which the response must
// answer; RelayState names the attempt, and a cookie binds it to this
// browser.
func (s *Server) startSAML(ctx context.Context, orgID uuid.UUID, p store.IdentityProvider, attempt store.InsertSignInAttemptParams) (api.StartSignInResponseObject, error) {
	idp, err := idpOf(p)
	if err != nil {
		return nil, err
	}
	attemptID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	location, requestID, err := s.spFor(orgID).AuthnRequest(idp, attemptID.String())
	if err != nil {
		return nil, err
	}
	attempt.ID, attempt.ExpiresAt = attemptID, time.Now().Add(attemptTTL)
	attempt.SamlRequestID = pgtype.Text{String: requestID, Valid: true}
	err = s.cluster.Tx(system(ctx), orgID.String(), func(tx pgx.Tx) error {
		return store.New(tx).InsertSignInAttempt(ctx, attempt)
	})
	if err != nil {
		return nil, err
	}
	// The provider posts the response back from its own site: the cookie
	// must go with a cross-site POST.
	setCrossSiteCookie(ctx, attemptCookie, orgID.String()+"."+attemptID.String(), attemptTTL)
	return api.StartSignIn302Response{Headers: api.StartSignIn302ResponseHeaders{Location: &location}}, nil
}

func samlFound(location string) api.FinishSamlSignInResponseObject {
	return api.FinishSamlSignIn302Response{Headers: api.FinishSamlSignIn302ResponseHeaders{Location: &location}}
}

// FinishSamlSignIn is the org's assertion consumer service: the provider's
// response, posted by the browser that started the attempt.
func (s *Server) FinishSamlSignIn(ctx context.Context, req api.FinishSamlSignInRequestObject) (api.FinishSamlSignInResponseObject, error) {
	orgID := req.OrgId
	var posted, relay string
	if req.Body != nil {
		if req.Body.SAMLResponse != nil {
			posted = *req.Body.SAMLResponse
		}
		if req.Body.RelayState != nil {
			relay = *req.Body.RelayState
		}
	}
	cookieOrg, attemptID, ok := parseAttemptCookie(cookieValue(ctx, attemptCookie))
	if !ok || cookieOrg != orgID {
		// Identity-provider-initiated (a dashboard tile): nothing in it is
		// taken, but the person meant to sign in, so a sign-in of our own
		// starts, which the provider answers at once.
		if posted != "" && saml.Unsolicited(posted) {
			s.logger.Info("unsolicited SAML response: starting a sign-in instead", "org_id", orgID)
			return samlFound(s.cfg.PublicURL + "/v1/sign-in/start?" + url.Values{"org_id": {orgID.String()}}.Encode()), nil
		}
		return samlFound(s.backURL(s.cfg.MainApp, errAttemptExpired, nil)), nil
	}
	if relay != attemptID.String() {
		return samlFound(s.backURL(s.cfg.MainApp, errAttemptExpired, nil)), nil
	}
	setCrossSiteCookie(ctx, attemptCookie, "", 0)

	var attempt store.SignInAttempt
	var p store.IdentityProvider
	err := s.cluster.Tx(system(ctx), orgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if attempt, err = q.UseSignInAttempt(ctx, store.UseSignInAttemptParams{OrgID: orgID, ID: attemptID}); err != nil {
			return err
		}
		p, err = q.GetIdentityProvider(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return samlFound(s.backURL(s.cfg.MainApp, errAttemptExpired, nil)), nil
	}
	if err != nil {
		return nil, err
	}
	refused := func(reason string) api.FinishSamlSignInResponseObject {
		s.logger.Warn("SAML sign-in refused", "org_id", orgID, "reason", reason)
		return samlFound(s.backForURL(attempt, errProviderRefused, nil))
	}
	if p.Preset != presetSAML || !attempt.SamlRequestID.Valid {
		return refused("not_saml"), nil
	}
	idp, err := idpOf(p)
	if err != nil {
		return nil, err
	}
	a, err := s.spFor(orgID).Verify(idp, posted, attempt.SamlRequestID.String, time.Now())
	var no *saml.Refused
	if errors.As(err, &no) {
		return refused(no.Reason), nil
	}
	if err != nil {
		return nil, err
	}
	// Once only: the id is remembered until the assertion would have
	// expired anyway.
	var fresh int64
	err = s.cluster.Tx(system(ctx), orgID.String(), func(tx pgx.Tx) error {
		var err error
		fresh, err = store.New(tx).RecordSamlAssertion(ctx, store.RecordSamlAssertionParams{OrgID: orgID, AssertionID: a.ID, ExpiresAt: a.NotOnOrAfter})
		return err
	})
	if err != nil {
		return nil, err
	}
	if fresh == 0 {
		return refused("replayed"), nil
	}
	address, name, err := mappingOf(p).Resolve(a)
	if err != nil {
		return refused("no_address"), nil
	}
	location, signedIn, err := s.finishProviderSignIn(ctx, orgID, attempt, presetSAML, asserted{Email: address, Name: name, Subject: a.Subject()})
	if err != nil {
		return nil, err
	}
	// The first sign-in that got all the way through proves the provider
	// as saved: what the test before saving could not.
	if signedIn && !p.VerifiedAt.Valid {
		var n int64
		err := s.cluster.Tx(system(ctx), orgID.String(), func(tx pgx.Tx) error {
			var err error
			n, err = store.New(tx).MarkSamlProviderVerified(ctx, store.MarkSamlProviderVerifiedParams{OrgID: orgID, Issuer: p.Issuer})
			return err
		})
		if err != nil {
			return nil, err
		}
		if n > 0 {
			if err := s.recorder.Record(ctx, audit.Event{
				OrgID: orgID.String(), Action: "identity_provider.verified", TargetType: "identity_provider", TargetID: p.ID.String(),
				Details: map[string]any{"preset": presetSAML, "issuer": p.Issuer},
				Actor:   db.SystemActor("identity"),
			}); err != nil {
				return nil, err
			}
		}
	}
	return samlFound(location), nil
}

// GetSamlServiceProviderMetadata is the org's service provider metadata,
// public: fixed by the org's id, it says nothing about the org.
func (s *Server) GetSamlServiceProviderMetadata(_ context.Context, req api.GetSamlServiceProviderMetadataRequestObject) (api.GetSamlServiceProviderMetadataResponseObject, error) {
	raw, err := s.spFor(req.OrgId).Metadata()
	if err != nil {
		return nil, err
	}
	return api.GetSamlServiceProviderMetadata200ApplicationsamlmetadataXmlResponse{Body: bytes.NewReader(raw), ContentLength: int64(len(raw))}, nil
}

// GetSamlServiceProvider is what the admin sets up at the provider.
func (s *Server) GetSamlServiceProvider(ctx context.Context, req api.GetSamlServiceProviderRequestObject) (api.GetSamlServiceProviderResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.SSO); err != nil {
		return api.GetSamlServiceProvider403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to configure the identity provider."}, nil
	}
	return api.GetSamlServiceProvider200JSONResponse(s.samlServiceProvider(req.OrgId)), nil
}

// SetSsoEnforcement turns on or off the requirement that the org's domain
// signs in through its provider. An Owner's alone, and only once the
// provider is verified, so nobody is required to use a provider that has
// never worked.
func (s *Server) SetSsoEnforcement(ctx context.Context, req api.SetSsoEnforcementRequestObject) (api.SetSsoEnforcementResponseObject, error) {
	if err := s.owner(ctx, req.OrgId); err != nil {
		if status, e := refusal(err, "Only an Owner of the organization decides whether single sign-on is required."); status == 401 {
			return api.SetSsoEnforcement401JSONResponse(e), nil
		} else {
			return api.SetSsoEnforcement403JSONResponse(e), nil
		}
	}
	if req.Body == nil {
		return api.SetSsoEnforcement400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Say whether single sign-on is required."}}, nil
	}
	want := req.Body.Enforced
	var p store.IdentityProvider
	var changed, unverified bool
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if p, err = q.GetIdentityProvider(ctx, req.OrgId); err != nil {
			return err
		}
		if want && !verified(p) {
			unverified = true
			return nil
		}
		if p.SsoEnforced == want {
			return nil
		}
		changed = true
		p, err = q.SetSsoEnforced(ctx, store.SetSsoEnforcedParams{OrgID: req.OrgId, SsoEnforced: want})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetSsoEnforcement404JSONResponse{Code: "identity_provider.not_configured", Message: "This organization has no identity provider."}, nil
	}
	if err != nil {
		return nil, err
	}
	if unverified {
		return api.SetSsoEnforcement409JSONResponse{Code: "identity_provider.not_verified",
			Message: "Single sign-on can be required once the provider has proven itself: for SAML, once someone has signed in through it."}, nil
	}
	if changed {
		if err := s.recorder.Record(ctx, audit.Event{
			OrgID: req.OrgId.String(), Action: "identity_provider.enforcement_changed", TargetType: "identity_provider", TargetID: p.ID.String(),
			Details: map[string]any{"enforced": want, "preset": p.Preset},
		}); err != nil {
			return nil, err
		}
	}
	return api.SetSsoEnforcement200JSONResponse(s.toAPI(p)), nil
}

// ssoRequiredBy is the org that requires single sign-on of an address, if
// one does now: the org that has proven the address's domain, with
// enforcement on and its provider verified.
func (s *Server) ssoRequiredBy(ctx context.Context, address string) (uuid.UUID, bool, error) {
	domain := address[strings.LastIndex(address, "@")+1:]
	orgID, err := s.orgs.ByDomain(ctx, domain)
	if errors.Is(err, ErrNotFound) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	var p store.IdentityProvider
	err = s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).GetIdentityProvider(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return orgID, enforcing(p), nil
}

// activeOwner is whether the memberships make the person an active Owner of org.
func activeOwner(all []Membership, org uuid.UUID) bool {
	for _, m := range all {
		if m.OrgID == org && m.Status == "active" && m.Role == string(authz.Owner) {
			return true
		}
	}
	return false
}
