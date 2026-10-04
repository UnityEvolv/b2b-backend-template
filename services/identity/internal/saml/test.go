package saml

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// The checks a provider's metadata passes before it is saved, in order.
const (
	CheckMetadata     = "metadata"
	CheckEntityID     = "entity_id"
	CheckSSOURL       = "sso_url"
	CheckCertificates = "certificates"
)

// The inputs a failed check names.
const (
	FieldMetadataURL = "saml.metadata_url"
	FieldMetadataXML = "saml.metadata_xml"
)

// Check is one step of the test, as oidc.Check: whether it passed and, when
// not, the input to fix. Message is for the admin.
type Check struct {
	Name    string
	OK      bool
	Field   string
	Message string
}

// Tested is the outcome of Test: the provider as it would be saved, and
// the checks.
type Tested struct {
	IdP    IdP
	Checks []Check
	// ExpiresAt is when the last of the saved certificates expires: when
	// sign-in stops working unless the metadata is saved again.
	ExpiresAt time.Time
}

// OK is whether every check passed.
func (t Tested) OK() bool {
	for _, c := range t.Checks {
		if !c.OK {
			return false
		}
	}
	return len(t.Checks) > 0
}

// Source is where the metadata comes from: a URL, fetched now, or a
// document the admin uploaded.
type Source struct {
	URL string
	XML []byte
}

// Test is what a provider's metadata must pass before it is saved, without
// anyone signing in:
//
//  1. metadata: the document is fetched (URL) or read (upload), and is one
//     identity provider's SAML 2.0 metadata.
//  2. entity_id: it names the provider's entity id, and it is not this
//     service provider's own (the wrong document uploaded).
//  3. sso_url: it offers single sign-on over the HTTP-Redirect binding at
//     an https URL.
//  4. certificates: it lists a signing certificate with an RSA key of 2048
//     bits or more (or ECDSA) that has not expired. Expired ones are
//     dropped; the rest are what signatures are checked against.
//
// What it cannot prove without a person signing in: that the provider has
// this service provider set up (entity id, ACS URL), that it signs the
// assertion with the key the metadata lists, and that it sends the
// attributes the mapping names. The first sign-in proves all of it, which
// is when the provider counts as verified.
//
// checkURL judges a URL the admin gave (https, or http on a laptop); h is
// the client the URL is fetched with (pkg/egress).
func Test(ctx context.Context, h *http.Client, checkURL func(string) error, src Source, sp SP, now time.Time) Tested {
	var out Tested
	field := FieldMetadataXML
	if src.URL != "" {
		field = FieldMetadataURL
	}
	fail := func(name, field, format string, args ...any) Tested {
		out.Checks = append(out.Checks, Check{Name: name, Field: field, Message: fmt.Sprintf(format, args...)})
		return out
	}
	pass := func(name, format string, args ...any) {
		out.Checks = append(out.Checks, Check{Name: name, OK: true, Message: fmt.Sprintf(format, args...)})
	}

	raw := src.XML
	where := "The uploaded metadata"
	if src.URL != "" {
		where = "The metadata at " + src.URL
		if err := checkURL(src.URL); err != nil {
			return fail(CheckMetadata, field, "The metadata URL must be an https URL (%s).", err)
		}
		var err error
		if raw, err = Fetch(ctx, h, src.URL); err != nil {
			return fail(CheckMetadata, field, "The metadata at %s could not be read (%s).", src.URL, err)
		}
	}
	md, err := ParseMetadata(raw)
	if err != nil {
		return fail(CheckMetadata, field, "%s is %s.", where, err)
	}
	pass(CheckMetadata, "%s was read.", where)

	switch {
	case md.EntityID == "":
		return fail(CheckEntityID, field, "The metadata names no entity id.")
	case len(md.EntityID) > 500:
		return fail(CheckEntityID, field, "The metadata's entity id is longer than 500 characters.")
	case md.EntityID == sp.EntityID:
		return fail(CheckEntityID, field, "This is this service's own metadata; upload the identity provider's.")
	}
	pass(CheckEntityID, "The identity provider is %s.", md.EntityID)

	switch {
	case md.RedirectURL == "" && md.PostURL != "":
		return fail(CheckSSOURL, field, "The provider offers single sign-on only over HTTP-POST. Sign-in sends the HTTP-Redirect binding, which every common provider supports: turn it on, or use the metadata that lists it.")
	case md.RedirectURL == "":
		return fail(CheckSSOURL, field, "The metadata lists no single sign-on service.")
	case len(md.RedirectURL) > 1000:
		return fail(CheckSSOURL, field, "The single sign-on URL is longer than 1000 characters.")
	}
	if err := checkURL(md.RedirectURL); err != nil {
		return fail(CheckSSOURL, field, "The single sign-on URL %s is not an https URL.", md.RedirectURL)
	}
	pass(CheckSSOURL, "People are sent to %s to sign in.", md.RedirectURL)

	var usable []*x509.Certificate
	weak := 0
	for _, c := range md.Certs {
		if !usableKey(c) {
			weak++
			continue
		}
		usable = append(usable, c)
	}
	keep, expired := current(usable, now)
	switch {
	case len(md.Certs) == 0 && md.BadCerts > 0:
		return fail(CheckCertificates, field, "None of the metadata's %d signing certificate(s) could be read.", md.BadCerts)
	case len(md.Certs) == 0:
		return fail(CheckCertificates, field, "The metadata lists no signing certificate, and every assertion must be signed.")
	case len(usable) == 0:
		return fail(CheckCertificates, field, "The signing certificate's key is too weak: RSA of 2048 bits or more, or ECDSA, is required.")
	case len(keep) == 0:
		return fail(CheckCertificates, field, "The signing certificate expired on %s. Renew it at the provider and use the new metadata.", latest(usable).Format("2 January 2006"))
	}
	if len(keep) > 10 {
		return fail(CheckCertificates, field, "The metadata lists more than 10 signing certificates.")
	}
	out.ExpiresAt = latest(keep)
	msg := fmt.Sprintf("%d signing certificate(s); the last expires on %s.", len(keep), out.ExpiresAt.Format("2 January 2006"))
	if expired > 0 {
		msg += fmt.Sprintf(" %d expired one(s) are ignored.", expired)
	}
	if weak > 0 {
		msg += fmt.Sprintf(" %d with a weak key are ignored.", weak)
	}
	if out.ExpiresAt.Sub(now) < 30*24*time.Hour {
		msg += " Renew it soon: sign-in stops when it expires."
	}
	pass(CheckCertificates, "%s", msg)
	out.IdP = IdP{EntityID: md.EntityID, SSOURL: md.RedirectURL, Certs: keep}
	return out
}

// latest is the last NotAfter among certs.
func latest(certs []*x509.Certificate) time.Time {
	var t time.Time
	for _, c := range certs {
		if c.NotAfter.After(t) {
			t = c.NotAfter
		}
	}
	return t
}

// Recheck is a saved provider's certificates judged again at now, for a
// change that keeps the metadata: the same rule as Test's last check.
func Recheck(idp IdP, now time.Time) (Tested, bool) {
	keep, _ := current(idp.Certs, now)
	out := Tested{IdP: IdP{EntityID: idp.EntityID, SSOURL: idp.SSOURL, Certs: keep}}
	if len(keep) == 0 {
		out.Checks = append(out.Checks, Check{Name: CheckCertificates, Field: FieldMetadataURL,
			Message: "Every saved signing certificate has expired. Renew it at the provider and use the new metadata."})
		return out, false
	}
	out.ExpiresAt = latest(keep)
	out.Checks = append(out.Checks, Check{Name: CheckCertificates, OK: true,
		Message: fmt.Sprintf("The saved metadata is kept: %d signing certificate(s); the last expires on %s.", len(keep), out.ExpiresAt.Format("2 January 2006"))})
	return out, true
}
