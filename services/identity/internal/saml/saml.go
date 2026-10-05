// Package saml is the SAML 2.0 service provider an organization's people sign
// in through: the identity provider's metadata read and checked, the
// AuthnRequest that sends the browser there (HTTP-Redirect binding), this
// service's own metadata, and the verification of the response the browser
// posts back (HTTP-POST binding).
//
// The protocol's types, the metadata model and the AuthnRequest are
// github.com/crewjam/saml's. The response is verified here, with the XML
// signature library crewjam uses (github.com/russellhaering/goxmldsig),
// because a sign-in needs more than crewjam's ParseXMLResponse insists on:
// the assertion itself must be signed (crewjam accepts a signed response
// around an unsigned assertion), it must carry an audience and a bearer
// subject confirmation (crewjam passes an assertion with neither), and
// what is read is the element the signature covers, as the signature
// library hands it back after verifying, never the document it came in.
// That last rule is what defeats signature wrapping: whatever else an
// attacker puts in the document, only the signed bytes are read.
//
// Nothing here logs, and no error carries an assertion, an address or a
// name: the caller may log them.
package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
)

// The namespaces a response is read in.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	// bearer is the subject confirmation a browser sign-in carries.
	bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// SP is this service as one organization's service provider: what the
// identity provider is told, and what every assertion must be addressed to.
type SP struct {
	// EntityID is the audience every assertion must name. It is the URL of
	// the metadata, as is customary.
	EntityID string
	// ACSURL is where the browser posts the response: the Destination of
	// the response and the Recipient of the assertion.
	ACSURL string
}

// SPFor is the service provider for an org, under the service's public URL.
// Fixed by the org's id, so the identity provider can be set up with it
// before anything is saved here.
func SPFor(publicURL, orgID string) SP {
	base := strings.TrimSuffix(publicURL, "/") + "/v1/sign-in/saml/" + url.PathEscape(orgID)
	return SP{EntityID: base + "/metadata", ACSURL: base + "/acs"}
}

// Metadata is this service provider's metadata, for the identity provider:
// the entity id, the assertion consumer service (HTTP-POST), and that
// assertions must be signed. No key: requests are not signed and assertions
// are not encrypted (docs/sso.md says why).
func (sp SP) Metadata() ([]byte, error) {
	no, yes := false, true
	ed := saml.EntityDescriptor{
		EntityID: sp.EntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{ProtocolSupportEnumeration: nsProtocol},
				NameIDFormats:  []saml.NameIDFormat{saml.EmailAddressNameIDFormat},
			},
			AuthnRequestsSigned:  &no,
			WantAssertionsSigned: &yes,
			AssertionConsumerServices: []saml.IndexedEndpoint{
				{Binding: saml.HTTPPostBinding, Location: sp.ACSURL, Index: 0, IsDefault: &yes},
			},
		}},
	}
	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// AuthnRequest is the URL that sends the browser to the identity provider
// with a fresh request, and the request's id, which the response must
// answer. relayState comes back with the response; it names the sign-in
// attempt and must be URL-safe.
func (sp SP) AuthnRequest(idp IdP, relayState string) (location, requestID string, err error) {
	csp := sp.crewjam(idp)
	req, err := csp.MakeAuthenticationRequest(idp.SSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}
	u, err := req.Redirect(url.QueryEscape(relayState), csp)
	if err != nil {
		return "", "", err
	}
	return u.String(), req.ID, nil
}

func (sp SP) crewjam(idp IdP) *saml.ServiceProvider {
	acs, _ := url.Parse(sp.ACSURL)
	out := &saml.ServiceProvider{
		EntityID: sp.EntityID,
		IDPMetadata: &saml.EntityDescriptor{EntityID: idp.EntityID, IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor:        saml.SSODescriptor{},
			SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: idp.SSOURL}},
		}}},
		// Unspecified: no Format in the request, so every provider answers
		// with the name id it is set up to send.
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
	}
	if acs != nil {
		out.AcsURL = *acs
	}
	return out
}

// MaxResponse caps a posted response, base64 included.
const MaxResponse = 512 << 10

// decode is a posted SAMLResponse as XML. Some providers wrap the base64.
func decode(posted string) ([]byte, error) {
	if posted == "" || len(posted) > MaxResponse {
		return nil, errors.New("no response, or one too large")
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, posted)
	return base64.StdEncoding.DecodeString(clean)
}

// inflate is a SAMLRequest from the HTTP-Redirect binding, as XML: for
// tests that play the identity provider.
func inflate(param string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20))
}

// Request is an AuthnRequest as the identity provider reads it.
type Request struct {
	ID, Issuer, ACSURL, Destination string
}

// ReadRequest is the AuthnRequest in a redirect to the identity provider,
// and its RelayState: what an identity provider reads from it. For tests.
func ReadRequest(location string) (Request, string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return Request{}, "", err
	}
	raw, err := inflate(u.Query().Get("SAMLRequest"))
	if err != nil {
		return Request{}, "", fmt.Errorf("SAMLRequest: %w", err)
	}
	var req saml.AuthnRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		return Request{}, "", err
	}
	out := Request{ID: req.ID, ACSURL: req.AssertionConsumerServiceURL, Destination: req.Destination}
	if req.Issuer != nil {
		out.Issuer = req.Issuer.Value
	}
	return out, u.Query().Get("RelayState"), nil
}
