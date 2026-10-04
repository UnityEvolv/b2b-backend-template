// Package samltest is a SAML identity provider for tests: a key and a
// certificate made when the test runs (nothing is committed), its metadata,
// and responses built to order, well formed or broken in exactly one way.
package samltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// IdP is an identity provider with its own signing key.
type IdP struct {
	EntityID string
	SSOURL   string
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
}

// New is an identity provider whose certificate is valid from an hour ago
// for a year.
func New(t testing.TB, entityID, ssoURL string) *IdP {
	t.Helper()
	return NewValid(t, entityID, ssoURL, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

// NewValid is an identity provider whose certificate is valid between
// notBefore and notAfter.
func NewValid(t testing.TB, entityID, ssoURL string, notBefore, notAfter time.Time) *IdP {
	t.Helper()
	key, cert := KeyPair(t, notBefore, notAfter, 2048)
	return &IdP{EntityID: entityID, SSOURL: ssoURL, Key: key, Cert: cert}
}

// KeyPair is a fresh RSA key of bits and a self-signed certificate for it.
func KeyPair(t testing.TB, notBefore, notAfter time.Time, bits int) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test identity provider"},
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// Metadata is the provider's metadata: its entity id, single sign-on over
// HTTP-Redirect and HTTP-POST, and its signing certificates (its own, and
// any others given).
func (i *IdP) Metadata(t testing.TB, extra ...*x509.Certificate) []byte {
	t.Helper()
	var keys []saml.KeyDescriptor
	for _, c := range append([]*x509.Certificate{i.Cert}, extra...) {
		keys = append(keys, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
			X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(c.Raw)}},
		}}})
	}
	ed := saml.EntityDescriptor{
		EntityID: i.EntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol", KeyDescriptors: keys,
			}},
			SingleSignOnServices: []saml.Endpoint{
				{Binding: saml.HTTPRedirectBinding, Location: i.SSOURL},
				{Binding: saml.HTTPPostBinding, Location: i.SSOURL},
			},
		}},
	}
	out, err := xml.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Answer is what one response says, and how it is signed. Built with
// Defaults and then changed: each field is what a test breaks.
type Answer struct {
	ResponseID, AssertionID string
	// InResponseTo is the request answered, on the response and the
	// confirmation; empty for an unsolicited one.
	InResponseTo string
	Destination  string
	Recipient    string
	Audience     string
	// Issuer is the response's and the assertion's.
	Issuer               string
	NameID, NameIDFormat string
	Attributes           map[string]string
	IssueInstant         time.Time
	NotOnOrAfter         time.Time
	// SignAssertion and SignResponse say what carries a signature, made
	// with SignKey and SignCert (the provider's own unless replaced).
	SignAssertion, SignResponse bool
	SignKey                     *rsa.PrivateKey
	SignCert                    *x509.Certificate
	// NoAudience leaves the audience restriction out; NoConfirmation the
	// bearer subject confirmation.
	NoAudience, NoConfirmation bool
	// Status is the response's status code; success when empty.
	Status string
}

// Defaults is a good answer to the request id from acs for audience,
// saying email: the assertion signed, not the response.
func (i *IdP) Defaults(requestID, acs, audience, email string) Answer {
	now := time.Now()
	return Answer{
		ResponseID: "_r" + randomID(), AssertionID: "_a" + randomID(), InResponseTo: requestID,
		Destination: acs, Recipient: acs, Audience: audience, Issuer: i.EntityID,
		NameID: email, NameIDFormat: string(saml.EmailAddressNameIDFormat),
		Attributes:   map[string]string{"email": email, "firstName": "Ada", "lastName": "Lovelace"},
		IssueInstant: now, NotOnOrAfter: now.Add(5 * time.Minute),
		SignAssertion: true, SignKey: i.Key, SignCert: i.Cert,
	}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Assertion is a's assertion, signed when a says so.
func (i *IdP) Assertion(t testing.TB, a Answer) *etree.Element {
	t.Helper()
	as := saml.Assertion{
		ID: a.AssertionID, IssueInstant: a.IssueInstant, Version: "2.0",
		Issuer:  saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: a.Issuer},
		Subject: &saml.Subject{NameID: &saml.NameID{Format: a.NameIDFormat, Value: a.NameID}},
		Conditions: &saml.Conditions{
			NotBefore: a.IssueInstant.Add(-time.Minute), NotOnOrAfter: a.NotOnOrAfter,
		},
		AuthnStatements: []saml.AuthnStatement{{AuthnInstant: a.IssueInstant, AuthnContext: saml.AuthnContext{
			AuthnContextClassRef: &saml.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
		}}},
	}
	if !a.NoConfirmation {
		as.Subject.SubjectConfirmations = []saml.SubjectConfirmation{{
			Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
			SubjectConfirmationData: &saml.SubjectConfirmationData{
				InResponseTo: a.InResponseTo, NotOnOrAfter: a.NotOnOrAfter, Recipient: a.Recipient,
			},
		}}
	}
	if !a.NoAudience {
		as.Conditions.AudienceRestrictions = []saml.AudienceRestriction{{Audience: saml.Audience{Value: a.Audience}}}
	}
	if len(a.Attributes) > 0 {
		st := saml.AttributeStatement{}
		for name, value := range a.Attributes {
			st.Attributes = append(st.Attributes, saml.Attribute{
				Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []saml.AttributeValue{{Type: "xs:string", Value: value}},
			})
		}
		as.AttributeStatements = []saml.AttributeStatement{st}
	}
	el := as.Element()
	if a.SignAssertion {
		el = Sign(t, el, a.SignKey, a.SignCert)
	}
	return el
}

// Response is a's response around the given assertions (a's own when none
// is given), signed when a says so.
func (i *IdP) Response(t testing.TB, a Answer, assertions ...*etree.Element) *etree.Element {
	t.Helper()
	if len(assertions) == 0 {
		assertions = []*etree.Element{i.Assertion(t, a)}
	}
	el := etree.NewElement("samlp:Response")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", a.ResponseID)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", a.IssueInstant.UTC().Format(time.RFC3339))
	if a.Destination != "" {
		el.CreateAttr("Destination", a.Destination)
	}
	if a.InResponseTo != "" {
		el.CreateAttr("InResponseTo", a.InResponseTo)
	}
	el.CreateElement("saml:Issuer").SetText(a.Issuer)
	status := a.Status
	if status == "" {
		status = saml.StatusSuccess
	}
	el.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", status)
	for _, as := range assertions {
		el.AddChild(as)
	}
	if a.SignResponse {
		el = Sign(t, el, a.SignKey, a.SignCert)
	}
	return el
}

// Sign is el with an enveloped signature (RSA-SHA256, exclusive
// canonicalization) by key, its certificate in KeyInfo.
func Sign(t testing.TB, el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// Encode is a response as the browser posts it: base64 of the document.
func Encode(t testing.TB, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
