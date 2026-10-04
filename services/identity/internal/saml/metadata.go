package saml

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// IdP is an identity provider as sign-in uses it: who it says it is, where
// the browser is sent, and the certificates its signatures are checked
// against.
type IdP struct {
	EntityID string
	// SSOURL is its single sign-on service for the HTTP-Redirect binding.
	SSOURL string
	Certs  []*x509.Certificate
}

// Metadata is what an identity provider's metadata document says, before
// any of it is judged: Test decides what is good enough to save.
type Metadata struct {
	EntityID string
	// RedirectURL and PostURL are its single sign-on services, by binding.
	RedirectURL, PostURL string
	// Certs is every signing certificate it lists that parses; BadCerts
	// counts those that do not.
	Certs    []*x509.Certificate
	BadCerts int
}

// MaxMetadata caps a metadata document, uploaded or fetched.
const MaxMetadata = 1 << 20

// ErrNotMetadata is a document that is not one identity provider's SAML
// metadata. Its message says why, for the admin.
var ErrNotMetadata = errors.New("not an identity provider's SAML metadata")

// ParseMetadata reads an identity provider's metadata: an EntityDescriptor,
// or an EntitiesDescriptor holding exactly one identity provider. A
// signature on the document is not checked: the document is trusted as the
// admin who uploaded it, or the https URL it came from.
func ParseMetadata(raw []byte) (Metadata, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Metadata{}, fmt.Errorf("%w: the document is empty", ErrNotMetadata)
	}
	if len(raw) > MaxMetadata {
		return Metadata{}, fmt.Errorf("%w: the document is larger than 1 MB", ErrNotMetadata)
	}
	// A document whose meaning changes when it is written back out is
	// refused before anything reads it.
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return Metadata{}, fmt.Errorf("%w: the XML is not well formed", ErrNotMetadata)
	}
	var ed saml.EntityDescriptor
	switch rootName(raw) {
	case "EntityDescriptor":
		if err := xml.Unmarshal(raw, &ed); err != nil {
			return Metadata{}, fmt.Errorf("%w: the EntityDescriptor could not be read", ErrNotMetadata)
		}
	case "EntitiesDescriptor":
		var all saml.EntitiesDescriptor
		if err := xml.Unmarshal(raw, &all); err != nil {
			return Metadata{}, fmt.Errorf("%w: the EntitiesDescriptor could not be read", ErrNotMetadata)
		}
		var idps []saml.EntityDescriptor
		collect(all, &idps)
		if len(idps) != 1 {
			return Metadata{}, fmt.Errorf("%w: it describes %d identity providers; use the metadata of the one application set up for this organization", ErrNotMetadata, len(idps))
		}
		ed = idps[0]
	default:
		return Metadata{}, fmt.Errorf("%w: it is neither an EntityDescriptor nor an EntitiesDescriptor", ErrNotMetadata)
	}
	if len(ed.IDPSSODescriptors) == 0 {
		return Metadata{}, fmt.Errorf("%w: it has no IDPSSODescriptor (a service provider's metadata, perhaps)", ErrNotMetadata)
	}
	out := Metadata{EntityID: strings.TrimSpace(ed.EntityID)}
	seen := map[string]bool{}
	for _, d := range ed.IDPSSODescriptors {
		if !strings.Contains(d.ProtocolSupportEnumeration, nsProtocol) {
			continue
		}
		for _, s := range d.SingleSignOnServices {
			switch s.Binding {
			case saml.HTTPRedirectBinding:
				if out.RedirectURL == "" {
					out.RedirectURL = strings.TrimSpace(s.Location)
				}
			case saml.HTTPPostBinding:
				if out.PostURL == "" {
					out.PostURL = strings.TrimSpace(s.Location)
				}
			}
		}
		for _, k := range d.KeyDescriptors {
			// Encryption keys are not signing keys; an unlabelled key is both.
			if k.Use != "" && k.Use != "signing" {
				continue
			}
			for _, c := range k.KeyInfo.X509Data.X509Certificates {
				data := strings.Join(strings.Fields(c.Data), "")
				if seen[data] {
					continue
				}
				seen[data] = true
				der, err := base64.StdEncoding.DecodeString(data)
				if err != nil {
					out.BadCerts++
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					out.BadCerts++
					continue
				}
				out.Certs = append(out.Certs, cert)
			}
		}
	}
	return out, nil
}

// metadataNS is the namespace of a metadata document's root.
const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"

// rootName is the local name of the document's root element when it is in
// the metadata namespace, else "".
func rootName(raw []byte) string {
	d := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if start, ok := tok.(xml.StartElement); ok {
			if start.Name.Space != metadataNS {
				return ""
			}
			return start.Name.Local
		}
	}
}

func collect(all saml.EntitiesDescriptor, into *[]saml.EntityDescriptor) {
	for _, e := range all.EntityDescriptors {
		if len(e.IDPSSODescriptors) > 0 {
			*into = append(*into, e)
		}
	}
	for _, nested := range all.EntitiesDescriptors {
		collect(nested, into)
	}
}

// Fetch reads a metadata document from its URL with h, the service's
// client for addresses an admin chose (pkg/egress: public addresses only,
// deployed). At most MaxMetadata is read.
func Fetch(ctx context.Context, h *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxMetadata+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxMetadata {
		return nil, errors.New("the document is larger than 1 MB")
	}
	return body, nil
}

// usableKey is whether a certificate's key is one a signature is accepted
// from: RSA of 2048 bits or more, or ECDSA.
func usableKey(c *x509.Certificate) bool {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize >= 256
	}
	return false
}

// current is the certificates that have not expired at now (one not valid
// yet is kept: it is the next one, published ahead of a rotation), and the
// number that have.
func current(certs []*x509.Certificate, now time.Time) (keep []*x509.Certificate, expired int) {
	for _, c := range certs {
		if now.After(c.NotAfter) {
			expired++
			continue
		}
		keep = append(keep, c)
	}
	return keep, expired
}
