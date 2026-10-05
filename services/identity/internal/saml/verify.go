package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// Skew is the clock difference tolerated between the identity provider and
// this service, on every time an assertion carries.
const Skew = 3 * time.Minute

// MaxAge is how long after the provider issued it an assertion is still
// taken, skew included: a response is posted by the browser the moment it
// is made.
const MaxAge = 5 * time.Minute

// The reasons a response is refused. Each is safe to log; none carries
// anything from the response.
const (
	ReasonMalformed    = "malformed"
	ReasonStatus       = "status"
	ReasonDestination  = "destination"
	ReasonInResponseTo = "in_response_to"
	ReasonIssuer       = "issuer"
	ReasonEncrypted    = "encrypted"
	ReasonAssertions   = "assertion_count"
	ReasonUnsigned     = "unsigned"
	ReasonSignature    = "signature"
	ReasonSubject      = "subject"
	ReasonRecipient    = "recipient"
	ReasonExpired      = "expired"
	ReasonNotYetValid  = "not_yet_valid"
	ReasonAudience     = "audience"
)

// Refused is a response that is not accepted, with the reason.
type Refused struct {
	Reason string
	// detail is for tests; Error leaves it out of anything logged.
	detail string
}

func (r *Refused) Error() string { return "saml: response refused: " + r.Reason }

// Detail is what exactly was wrong, for a test's failure message. Never
// logged: it can quote the response.
func (r *Refused) Detail() string { return r.detail }

func refuse(reason, format string, args ...any) error {
	return &Refused{Reason: reason, detail: fmt.Sprintf(format, args...)}
}

// Assertion is what a verified assertion says, read from the signed bytes.
type Assertion struct {
	// ID is the assertion's, for the replay check.
	ID string
	// NameID and its format: the subject.
	NameID, NameIDFormat string
	// Attributes by name, and by friendly name where it differs.
	Attributes map[string][]string
	// NotOnOrAfter is when it stops being acceptable: the latest of its
	// conditions and its bearer confirmation, plus the skew. A replay check
	// remembers its id until then.
	NotOnOrAfter time.Time
}

// Unsolicited is whether a posted response answers no request: an
// identity-provider-initiated sign-in. Read without verifying anything;
// the answer only decides whether to start a sign-in of our own, and
// nothing in such a response is ever accepted.
func Unsolicited(posted string) bool {
	raw, err := decode(posted)
	if err != nil {
		return false
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return false
	}
	return doc.Root().SelectAttrValue("InResponseTo", "") == ""
}

// Verify checks a posted SAMLResponse that answers the request requestID,
// and returns what its assertion says. Everything is required:
//
//   - the response is well formed and survives being written back out
//     unchanged (no XML that two parsers would read differently);
//   - its status is success, its Destination is the ACS URL, its
//     InResponseTo is the request, and its Issuer (when present) is the
//     provider;
//   - a signature on the response itself, if there is one, verifies;
//   - it holds exactly one assertion, in plain text (an encrypted one is
//     refused: no key is published to encrypt to);
//   - that assertion carries its own enveloped signature, which verifies
//     against one of the provider's certificates, currently valid;
//   - and the assertion read is the one the signature library returns
//     after verifying it: issuer, a bearer subject confirmation whose
//     Recipient is the ACS URL, InResponseTo the request and NotOnOrAfter
//     not past, conditions in their time window, and an audience
//     restriction naming this service provider (each restriction must).
func (sp SP) Verify(idp IdP, posted, requestID string, now time.Time) (Assertion, error) {
	raw, err := decode(posted)
	if err != nil {
		return Assertion{}, refuse(ReasonMalformed, "decode: %v", err)
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return Assertion{}, refuse(ReasonMalformed, "round trip: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return Assertion{}, refuse(ReasonMalformed, "parse: %v", err)
	}
	root := doc.Root()
	if root.Tag != "Response" || root.NamespaceURI() != nsProtocol {
		return Assertion{}, refuse(ReasonMalformed, "root is %s", root.Tag)
	}

	// The response's own signature, when it has one, must verify; the
	// assertion's is required whatever this says.
	if sig, err := child(root, nsDSig, "Signature"); err != nil {
		return Assertion{}, err
	} else if sig != nil {
		if _, err := verified(root, idp.Certs, now); err != nil {
			return Assertion{}, err
		}
	}
	var resp saml.Response
	if err := unmarshal(root, &resp); err != nil {
		return Assertion{}, refuse(ReasonMalformed, "response: %v", err)
	}
	if resp.Status.StatusCode.Value != saml.StatusSuccess {
		return Assertion{}, refuse(ReasonStatus, "status %s", resp.Status.StatusCode.Value)
	}
	if resp.Destination != sp.ACSURL {
		return Assertion{}, refuse(ReasonDestination, "destination %q", resp.Destination)
	}
	if requestID == "" || resp.InResponseTo != requestID {
		return Assertion{}, refuse(ReasonInResponseTo, "in response to %q", resp.InResponseTo)
	}
	if resp.Issuer != nil && strings.TrimSpace(resp.Issuer.Value) != idp.EntityID {
		return Assertion{}, refuse(ReasonIssuer, "response issuer %q", resp.Issuer.Value)
	}

	if enc, err := children(root, nsAssertion, "EncryptedAssertion"); err != nil {
		return Assertion{}, err
	} else if len(enc) > 0 {
		return Assertion{}, refuse(ReasonEncrypted, "encrypted assertion")
	}
	assertions, err := children(root, nsAssertion, "Assertion")
	if err != nil {
		return Assertion{}, err
	}
	if len(assertions) != 1 {
		return Assertion{}, refuse(ReasonAssertions, "%d assertions", len(assertions))
	}
	el := assertions[0]
	if sig, err := child(el, nsDSig, "Signature"); err != nil {
		return Assertion{}, err
	} else if sig == nil {
		return Assertion{}, refuse(ReasonUnsigned, "the assertion has no signature of its own")
	}
	// From here on, only what the signature covers is read.
	signed, err := verified(el, idp.Certs, now)
	if err != nil {
		return Assertion{}, err
	}
	var a saml.Assertion
	if err := unmarshal(signed, &a); err != nil {
		return Assertion{}, refuse(ReasonMalformed, "assertion: %v", err)
	}
	if a.ID == "" || a.ID != el.SelectAttrValue("ID", "") {
		return Assertion{}, refuse(ReasonSignature, "the signed element is not the assertion")
	}
	return sp.check(idp, a, requestID, now)
}

// check is the verified assertion's own rules.
func (sp SP) check(idp IdP, a saml.Assertion, requestID string, now time.Time) (Assertion, error) {
	if strings.TrimSpace(a.Issuer.Value) != idp.EntityID {
		return Assertion{}, refuse(ReasonIssuer, "assertion issuer %q", a.Issuer.Value)
	}
	if a.IssueInstant.IsZero() || now.After(a.IssueInstant.Add(MaxAge)) {
		return Assertion{}, refuse(ReasonExpired, "issued %s", a.IssueInstant)
	}
	if a.IssueInstant.After(now.Add(Skew)) {
		return Assertion{}, refuse(ReasonNotYetValid, "issued %s", a.IssueInstant)
	}
	if a.Subject == nil || a.Subject.NameID == nil || strings.TrimSpace(a.Subject.NameID.Value) == "" {
		return Assertion{}, refuse(ReasonSubject, "no subject name id")
	}
	// A bearer confirmation for this request, to this ACS, still open. Any
	// other bearer confirmation in the assertion must be just as good:
	// an assertion is not half for someone else.
	var until time.Time
	bearers := 0
	for _, c := range a.Subject.SubjectConfirmations {
		if c.Method != bearer {
			continue
		}
		bearers++
		d := c.SubjectConfirmationData
		switch {
		case d == nil:
			return Assertion{}, refuse(ReasonSubject, "bearer confirmation without data")
		case d.Recipient != sp.ACSURL:
			return Assertion{}, refuse(ReasonRecipient, "recipient %q", d.Recipient)
		case d.InResponseTo != requestID:
			return Assertion{}, refuse(ReasonInResponseTo, "assertion in response to %q", d.InResponseTo)
		case d.NotOnOrAfter.IsZero():
			return Assertion{}, refuse(ReasonExpired, "bearer confirmation without NotOnOrAfter")
		case !now.Before(d.NotOnOrAfter.Add(Skew)):
			return Assertion{}, refuse(ReasonExpired, "bearer confirmation ended %s", d.NotOnOrAfter)
		case !d.NotBefore.IsZero() && now.Add(Skew).Before(d.NotBefore):
			return Assertion{}, refuse(ReasonNotYetValid, "bearer confirmation starts %s", d.NotBefore)
		}
		if d.NotOnOrAfter.After(until) {
			until = d.NotOnOrAfter
		}
	}
	if bearers == 0 {
		return Assertion{}, refuse(ReasonSubject, "no bearer confirmation")
	}
	c := a.Conditions
	if c == nil {
		return Assertion{}, refuse(ReasonAudience, "no conditions")
	}
	if !c.NotBefore.IsZero() && now.Add(Skew).Before(c.NotBefore) {
		return Assertion{}, refuse(ReasonNotYetValid, "conditions start %s", c.NotBefore)
	}
	if !c.NotOnOrAfter.IsZero() {
		if !now.Before(c.NotOnOrAfter.Add(Skew)) {
			return Assertion{}, refuse(ReasonExpired, "conditions ended %s", c.NotOnOrAfter)
		}
		if c.NotOnOrAfter.After(until) {
			until = c.NotOnOrAfter
		}
	}
	if len(c.AudienceRestrictions) == 0 {
		return Assertion{}, refuse(ReasonAudience, "no audience restriction")
	}
	for _, r := range c.AudienceRestrictions {
		if strings.TrimSpace(r.Audience.Value) != sp.EntityID {
			return Assertion{}, refuse(ReasonAudience, "audience %q", r.Audience.Value)
		}
	}
	out := Assertion{
		ID: a.ID, NameID: strings.TrimSpace(a.Subject.NameID.Value), NameIDFormat: a.Subject.NameID.Format,
		Attributes: map[string][]string{}, NotOnOrAfter: until.Add(Skew),
	}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			var values []string
			for _, v := range attr.Values {
				if s := strings.TrimSpace(v.Value); s != "" {
					values = append(values, s)
				}
			}
			if attr.Name != "" {
				out.Attributes[attr.Name] = append(out.Attributes[attr.Name], values...)
			}
			if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
				out.Attributes[attr.FriendlyName] = append(out.Attributes[attr.FriendlyName], values...)
			}
		}
	}
	return out, nil
}

// verified is el's enveloped signature checked against each certificate in
// turn, and the element as the signature covers it: canonical, the
// signature removed, nothing outside it. A certificate in the signature's
// KeyInfo must be one of certs; a signature with no certificate there is
// tried against each.
func verified(el *etree.Element, certs []*x509.Certificate, now time.Time) (*etree.Element, error) {
	if len(certs) == 0 {
		return nil, refuse(ReasonSignature, "no certificate to check against")
	}
	// The element on its own, with the namespaces it inherits declared on it.
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, refuse(ReasonMalformed, "namespaces: %v", err)
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return nil, refuse(ReasonMalformed, "namespaces: %v", err)
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, refuse(ReasonMalformed, "detach: %v", err)
	}
	// A KeyInfo with only a key value (no certificate) says nothing the
	// metadata does not: drop it, so the metadata's certificates are used.
	if sig := detached.FindElement("./Signature"); sig != nil {
		if ki := sig.FindElement("./KeyInfo"); ki != nil && ki.FindElement(".//X509Certificate") == nil {
			sig.RemoveChild(ki)
		}
	}
	var last error
	for _, cert := range certs {
		v := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		v.IdAttribute = "ID"
		v.Clock = dsig.NewFakeClockAt(now)
		out, err := v.Validate(detached)
		if err == nil {
			return out, nil
		}
		last = err
	}
	return nil, refuse(ReasonSignature, "signature on %s: %v", el.Tag, last)
}

// child is el's one direct child in a namespace, or nil; two is malformed.
func child(el *etree.Element, ns, tag string) (*etree.Element, error) {
	all, err := children(el, ns, tag)
	if err != nil {
		return nil, err
	}
	switch len(all) {
	case 0:
		return nil, nil
	case 1:
		return all[0], nil
	}
	return nil, refuse(ReasonMalformed, "%d %s elements", len(all), tag)
}

// children is el's direct children with a tag in a namespace.
func children(el *etree.Element, ns, tag string) ([]*etree.Element, error) {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out, nil
}

// unmarshal reads an element into one of crewjam's types.
func unmarshal(el *etree.Element, into any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(raw, into)
}

// ErrNoAddress is an assertion that says no address the mapping can find.
var ErrNoAddress = errors.New("saml: no email address in the assertion")
