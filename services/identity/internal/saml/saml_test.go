package saml_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/saml"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/saml/samltest"
)

const org = "01922b5e-0000-7000-8000-0000000000a1"

var sp = saml.SPFor("https://api.example.test/identity/", org)

func newIdP(t *testing.T) (*samltest.IdP, saml.IdP) {
	t.Helper()
	i := samltest.New(t, "https://idp.example.test/app/1", "https://idp.example.test/sso")
	return i, saml.IdP{EntityID: i.EntityID, SSOURL: i.SSOURL, Certs: []*x509.Certificate{i.Cert}}
}

func TestSPForAndItsMetadata(t *testing.T) {
	if sp.EntityID != "https://api.example.test/identity/v1/sign-in/saml/"+org+"/metadata" || sp.ACSURL != "https://api.example.test/identity/v1/sign-in/saml/"+org+"/acs" {
		t.Fatalf("%+v", sp)
	}
	raw, err := sp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`entityID="` + sp.EntityID + `"`, `Location="` + sp.ACSURL + `"`, "HTTP-POST", `WantAssertionsSigned="true"`, `AuthnRequestsSigned="false"`} {
		if !strings.Contains(s, want) {
			t.Errorf("metadata lacks %s:\n%s", want, s)
		}
	}
	if strings.Contains(s, "Artifact") || strings.Contains(s, "KeyDescriptor") {
		t.Errorf("metadata offers what is not served:\n%s", s)
	}
	// An SP's metadata is not an identity provider's.
	if _, err := saml.ParseMetadata(raw); !errors.Is(err, saml.ErrNotMetadata) {
		t.Errorf("own metadata parsed as an IdP's: %v", err)
	}
}

func TestAuthnRequest(t *testing.T) {
	_, idp := newIdP(t)
	location, id, err := sp.AuthnRequest(idp, "attempt-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(location, idp.SSOURL+"?SAMLRequest=") || strings.Contains(location, "Signature=") {
		t.Fatalf("location: %s", location)
	}
	req, relay, err := saml.ReadRequest(location)
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != id || id == "" || req.Issuer != sp.EntityID || req.ACSURL != sp.ACSURL || req.Destination != idp.SSOURL || relay != "attempt-1" {
		t.Errorf("request: %+v %q", req, relay)
	}
	_, id2, _ := sp.AuthnRequest(idp, "attempt-2")
	if id2 == id {
		t.Error("request ids repeat")
	}
}

func TestVerifyAcceptsASignedAssertion(t *testing.T) {
	i, idp := newIdP(t)
	for name, change := range map[string]func(*samltest.Answer){
		"assertion signed":         func(*samltest.Answer) {},
		"assertion and response":   func(a *samltest.Answer) { a.SignResponse = true },
		"several attribute values": func(a *samltest.Answer) { a.Attributes["groups"] = "x" },
		"within the clock skew":    func(a *samltest.Answer) { a.NotOnOrAfter = time.Now().Add(-time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			a := i.Defaults("id-1", sp.ACSURL, sp.EntityID, "ada@acme.test")
			change(&a)
			got, err := sp.Verify(idp, samltest.Encode(t, i.Response(t, a)), "id-1", time.Now())
			if err != nil {
				t.Fatalf("%v (%s)", err, detail(err))
			}
			if got.ID != a.AssertionID || got.NameID != "ada@acme.test" || got.Attributes["email"][0] != "ada@acme.test" || got.NotOnOrAfter.Before(a.NotOnOrAfter) {
				t.Errorf("%+v", got)
			}
		})
	}
}

func detail(err error) string {
	var r *saml.Refused
	if errors.As(err, &r) {
		return r.Detail()
	}
	return ""
}

// Every way a response is refused, each broken in exactly one way.
func TestVerifyRefuses(t *testing.T) {
	i, idp := newIdP(t)
	other, _ := newIdP(t)
	cases := map[string]struct {
		change func(*samltest.Answer)
		reason string
	}{
		"unsigned":                       {func(a *samltest.Answer) { a.SignAssertion = false }, saml.ReasonUnsigned},
		"only the response signed":       {func(a *samltest.Answer) { a.SignAssertion, a.SignResponse = false, true }, saml.ReasonUnsigned},
		"signed by another key":          {func(a *samltest.Answer) { a.SignKey, a.SignCert = other.Key, other.Cert }, saml.ReasonSignature},
		"response signed by another key": {func(a *samltest.Answer) { a.SignResponse = true; a.SignKey, a.SignCert = other.Key, other.Cert }, saml.ReasonSignature},
		"another audience":               {func(a *samltest.Answer) { a.Audience = "https://other.test/sp" }, saml.ReasonAudience},
		"no audience":                    {func(a *samltest.Answer) { a.NoAudience = true }, saml.ReasonAudience},
		"another recipient":              {func(a *samltest.Answer) { a.Recipient = "https://evil.test/acs" }, saml.ReasonRecipient},
		"another destination":            {func(a *samltest.Answer) { a.Destination = "https://evil.test/acs" }, saml.ReasonDestination},
		"no destination":                 {func(a *samltest.Answer) { a.Destination = "" }, saml.ReasonDestination},
		"expired":                        {func(a *samltest.Answer) { a.NotOnOrAfter = time.Now().Add(-4 * time.Minute) }, saml.ReasonExpired},
		"issued long ago":                {func(a *samltest.Answer) { a.IssueInstant = time.Now().Add(-10 * time.Minute) }, saml.ReasonExpired},
		"another request":                {func(a *samltest.Answer) { a.InResponseTo = "id-other" }, saml.ReasonInResponseTo},
		"unsolicited":                    {func(a *samltest.Answer) { a.InResponseTo = "" }, saml.ReasonInResponseTo},
		"another issuer":                 {func(a *samltest.Answer) { a.Issuer = "https://evil.test/idp" }, saml.ReasonIssuer},
		"no bearer confirmation":         {func(a *samltest.Answer) { a.NoConfirmation = true }, saml.ReasonSubject},
		"a failed status":                {func(a *samltest.Answer) { a.Status = "urn:oasis:names:tc:SAML:2.0:status:Requester" }, saml.ReasonStatus},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := i.Defaults("id-1", sp.ACSURL, sp.EntityID, "ada@acme.test")
			c.change(&a)
			_, err := sp.Verify(idp, samltest.Encode(t, i.Response(t, a)), "id-1", time.Now())
			var r *saml.Refused
			if !errors.As(err, &r) || r.Reason != c.reason {
				t.Errorf("got %v (%s), want %s", err, detail(err), c.reason)
			}
		})
	}
	t.Run("no request to answer", func(t *testing.T) {
		a := i.Defaults("", sp.ACSURL, sp.EntityID, "ada@acme.test")
		if _, err := sp.Verify(idp, samltest.Encode(t, i.Response(t, a)), "", time.Now()); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("not base64 or not XML", func(t *testing.T) {
		for _, posted := range []string{"", "%%%", base64.StdEncoding.EncodeToString([]byte("<a><b></a>"))} {
			if _, err := sp.Verify(idp, posted, "id-1", time.Now()); err == nil {
				t.Errorf("accepted %q", posted)
			}
		}
	})
	t.Run("an expired certificate", func(t *testing.T) {
		old := samltest.NewValid(t, i.EntityID, i.SSOURL, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		a := old.Defaults("id-1", sp.ACSURL, sp.EntityID, "ada@acme.test")
		_, err := sp.Verify(saml.IdP{EntityID: old.EntityID, SSOURL: old.SSOURL, Certs: []*x509.Certificate{old.Cert}}, samltest.Encode(t, old.Response(t, a)), "id-1", time.Now())
		if r := new(saml.Refused); !errors.As(err, &r) || r.Reason != saml.ReasonSignature {
			t.Errorf("got %v", err)
		}
	})
	t.Run("changed after signing", func(t *testing.T) {
		a := i.Defaults("id-1", sp.ACSURL, sp.EntityID, "eve@acme.test")
		resp := i.Response(t, a)
		for _, v := range resp.FindElements(".//AttributeValue") {
			if v.Text() == "eve@acme.test" {
				v.SetText("ceo@acme.test")
			}
		}
		resp.FindElement(".//Subject/NameID").SetText("ceo@acme.test")
		_, err := sp.Verify(idp, samltest.Encode(t, resp), "id-1", time.Now())
		if r := new(saml.Refused); !errors.As(err, &r) || r.Reason != saml.ReasonSignature {
			t.Errorf("got %v", err)
		}
	})
	t.Run("encrypted", func(t *testing.T) {
		a := i.Defaults("id-1", sp.ACSURL, sp.EntityID, "ada@acme.test")
		enc := etree.NewElement("saml:EncryptedAssertion")
		enc.CreateElement("xenc:EncryptedData").CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		_, err := sp.Verify(idp, samltest.Encode(t, i.Response(t, a, enc)), "id-1", time.Now())
		if r := new(saml.Refused); !errors.As(err, &r) || r.Reason != saml.ReasonEncrypted {
			t.Errorf("got %v", err)
		}
	})
}

// Signature wrapping: the attacker holds a genuine signed assertion for
// themself (eve) and builds a document around it that says someone else
// (the ceo). Whatever the shape, only the signed bytes are read, so the
// forgery is refused or reads as eve.
func TestVerifyDefeatsSignatureWrapping(t *testing.T) {
	i, idp := newIdP(t)
	genuine := func() (samltest.Answer, *etree.Element) {
		a := i.Defaults("id-1", sp.ACSURL, sp.EntityID, "eve@acme.test")
		return a, i.Assertion(t, a)
	}
	forged := func(a samltest.Answer, id string) *etree.Element {
		f := a
		f.AssertionID, f.NameID, f.SignAssertion = id, "ceo@acme.test", false
		f.Attributes = map[string]string{"email": "ceo@acme.test"}
		return i.Assertion(t, f)
	}
	check := func(t *testing.T, resp *etree.Element) {
		t.Helper()
		got, err := sp.Verify(idp, samltest.Encode(t, resp), "id-1", time.Now())
		if err == nil && (got.NameID != "eve@acme.test" || got.Attributes["email"][0] != "eve@acme.test") {
			t.Fatalf("the forgery was read: %+v", got)
		}
		if err == nil {
			t.Fatalf("accepted")
		}
	}

	t.Run("a forged assertion beside the signed one", func(t *testing.T) {
		a, signed := genuine()
		check(t, i.Response(t, a, forged(a, "_forged"), signed))
	})
	t.Run("the signed one's signature moved onto a forgery with its id", func(t *testing.T) {
		a, signed := genuine()
		f := forged(a, a.AssertionID)
		sig := signed.FindElement("./Signature")
		signed.RemoveChild(sig)
		f.InsertChildAt(1, sig)
		check(t, i.Response(t, a, f))
	})
	t.Run("the signed one hidden inside a forgery", func(t *testing.T) {
		a, signed := genuine()
		f := forged(a, "_forged")
		f.FindElement("./Subject").AddChild(signed)
		check(t, i.Response(t, a, f))
	})
	t.Run("the signed one in the response's extensions, a forgery with its signature in its place", func(t *testing.T) {
		a, signed := genuine()
		f := forged(a, a.AssertionID)
		f.InsertChildAt(1, signed.FindElement("./Signature").Copy())
		resp := i.Response(t, a, f)
		ext := etree.NewElement("samlp:Extensions")
		ext.AddChild(signed)
		resp.InsertChildAt(2, ext)
		check(t, resp)
	})
	t.Run("a signed response wrapping a forged assertion", func(t *testing.T) {
		// The response's signature covers the whole response, so a forged
		// assertion inside it cannot survive; and an assertion must carry
		// its own signature anyway.
		a, _ := genuine()
		a.SignResponse = true
		resp := i.Response(t, a, forged(a, "_forged"))
		check(t, resp)
	})
	t.Run("a comment splitting the address", func(t *testing.T) {
		// The provider signed eve's real address; a comment added after
		// signing does not change the signed text, and the text read is
		// the whole signed one, so the domain check sees evil.test.
		a := i.Defaults("id-1", sp.ACSURL, sp.EntityID, "ceo@acme.test.evil.test")
		resp := i.Response(t, a)
		for _, v := range append(resp.FindElements(".//AttributeValue"), resp.FindElement(".//Subject/NameID")) {
			if v.Text() == "ceo@acme.test.evil.test" {
				v.SetText("ceo@acme.test")
				v.CreateComment("")
				v.CreateText(".evil.test")
			}
		}
		got, err := sp.Verify(idp, samltest.Encode(t, resp), "id-1", time.Now())
		if err != nil || got.NameID != "ceo@acme.test.evil.test" || got.Attributes["email"][0] != "ceo@acme.test.evil.test" {
			t.Fatalf("not the signed text: %+v %v", got, err)
		}
	})
}

func TestUnsolicited(t *testing.T) {
	i, _ := newIdP(t)
	a := i.Defaults("", sp.ACSURL, sp.EntityID, "ada@acme.test")
	if !saml.Unsolicited(samltest.Encode(t, i.Response(t, a))) {
		t.Error("unsolicited not seen")
	}
	a.InResponseTo = "id-1"
	if saml.Unsolicited(samltest.Encode(t, i.Response(t, a))) || saml.Unsolicited("garbage") {
		t.Error("solicited taken for unsolicited")
	}
}

func TestMapping(t *testing.T) {
	entra, _ := saml.ProfileNamed("entra")
	got, name, err := entra.Mapping.Resolve(saml.Assertion{NameID: "upn@acme.test", Attributes: map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"ada@acme.test"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    {"Ada"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":      {"Lovelace"},
	}})
	if err != nil || got != "ada@acme.test" || name != "Ada Lovelace" {
		t.Errorf("entra: %q %q %v", got, name, err)
	}
	generic, _ := saml.ProfileNamed(saml.ProfileGeneric)
	// No attribute: the NameID, when it is an address.
	got, name, err = generic.Mapping.Resolve(saml.Assertion{NameID: "ada@acme.test", NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", Attributes: map[string][]string{"name": {"Ada L."}}})
	if err != nil || got != "ada@acme.test" || name != "Ada L." {
		t.Errorf("name id: %q %q %v", got, name, err)
	}
	// A transient NameID is never an address, and nothing else is either.
	if _, _, err := generic.Mapping.Resolve(saml.Assertion{NameID: "ada@acme.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}); !errors.Is(err, saml.ErrNoAddress) {
		t.Errorf("transient: %v", err)
	}
	if _, _, err := generic.Mapping.Resolve(saml.Assertion{NameID: "a1b2c3", Attributes: map[string][]string{"email": {"Ada <ada@acme.test>"}}}); !errors.Is(err, saml.ErrNoAddress) {
		t.Errorf("display form: %v", err)
	}
	for _, p := range saml.Profiles {
		if p.Mapping.Email == "" || p.Label == "" {
			t.Errorf("profile %s", p.Name)
		}
	}
}

func TestMetadataTest(t *testing.T) {
	i, _ := newIdP(t)
	now := time.Now()
	local := func(string) error { return nil }
	tested := saml.Test(context.Background(), nil, local, saml.Source{XML: i.Metadata(t)}, sp, now)
	if !tested.OK() || tested.IdP.EntityID != i.EntityID || tested.IdP.SSOURL != i.SSOURL || len(tested.IdP.Certs) != 1 || !tested.ExpiresAt.Equal(i.Cert.NotAfter) {
		t.Fatalf("%+v", tested)
	}

	expired := samltest.NewValid(t, i.EntityID, i.SSOURL, now.Add(-48*time.Hour), now.Add(-time.Hour))
	_, weakCert := samltest.KeyPair(t, now.Add(-time.Hour), now.Add(time.Hour*24*400), 1024)
	fresh := saml.Test(context.Background(), nil, local, saml.Source{XML: i.Metadata(t, expired.Cert, weakCert)}, sp, now)
	if !fresh.OK() || len(fresh.IdP.Certs) != 1 || !strings.Contains(fresh.Checks[3].Message, "expired") || !strings.Contains(fresh.Checks[3].Message, "weak") {
		t.Errorf("expired and weak certificates kept: %+v", fresh)
	}

	for name, c := range map[string]struct {
		src   saml.Source
		check string
	}{
		"empty":           {saml.Source{XML: []byte(" ")}, saml.CheckMetadata},
		"not XML":         {saml.Source{XML: []byte("<a><b></a>")}, saml.CheckMetadata},
		"its own":         {saml.Source{XML: must(sp.Metadata())}, saml.CheckMetadata},
		"only expired":    {saml.Source{XML: expired.Metadata(t)}, saml.CheckCertificates},
		"only POST":       {saml.Source{XML: []byte(strings.Replace(string(i.Metadata(t)), "HTTP-Redirect", "HTTP-Artifact", 1))}, saml.CheckSSOURL},
		"no entity id":    {saml.Source{XML: []byte(strings.Replace(string(i.Metadata(t)), `entityID="`+i.EntityID+`"`, `entityID=""`, 1))}, saml.CheckEntityID},
		"plain http":      {saml.Source{XML: []byte(strings.ReplaceAll(string(i.Metadata(t)), "https://idp.example.test/sso", "http://idp.example.test/sso"))}, saml.CheckSSOURL},
		"no certificate":  {saml.Source{XML: []byte(strings.Replace(string(i.Metadata(t)), "signing", "encryption", 1))}, saml.CheckCertificates},
		"two providers":   {saml.Source{XML: []byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + string(i.Metadata(t)) + string(i.Metadata(t)) + `</EntitiesDescriptor>`)}, saml.CheckMetadata},
		"a URL not https": {saml.Source{URL: "http://idp.example.test/metadata"}, saml.CheckMetadata},
	} {
		t.Run(name, func(t *testing.T) {
			https := func(u string) error {
				if !strings.HasPrefix(u, "https://") {
					return errors.New("not https")
				}
				return nil
			}
			got := saml.Test(context.Background(), nil, https, c.src, sp, now)
			last := got.Checks[len(got.Checks)-1]
			if got.OK() || last.Name != c.check || last.OK || last.Field == "" {
				t.Errorf("%+v", got.Checks)
			}
		})
	}

	// One provider in an EntitiesDescriptor is fine.
	one := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + string(i.Metadata(t)) + `</EntitiesDescriptor>`
	if got := saml.Test(context.Background(), nil, local, saml.Source{XML: []byte(one)}, sp, now); !got.OK() {
		t.Errorf("entities: %+v", got.Checks)
	}
}

// The metadata URL is fetched with the service's client for addresses an
// admin chose: deployed, a private or loopback address is refused at
// connect time, whatever the URL says.
func TestMetadataURLIsPublicOnly(t *testing.T) {
	i, _ := newIdP(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(i.Metadata(t)) }))
	defer srv.Close()
	any := func(string) error { return nil }

	deployed := egress.Client(egress.Options{Timeout: 5 * time.Second})
	got := saml.Test(context.Background(), deployed, any, saml.Source{URL: srv.URL + "/metadata"}, sp, time.Now())
	if got.OK() || got.Checks[0].Name != saml.CheckMetadata || got.Checks[0].Field != saml.FieldMetadataURL || !strings.Contains(got.Checks[0].Message, "not a public address") {
		t.Errorf("a loopback metadata URL was fetched: %+v", got.Checks)
	}
	laptop := egress.Client(egress.Options{Local: true, Timeout: 5 * time.Second})
	if got := saml.Test(context.Background(), laptop, any, saml.Source{URL: srv.URL + "/metadata"}, sp, time.Now()); !got.OK() {
		t.Errorf("local: %+v", got.Checks)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
