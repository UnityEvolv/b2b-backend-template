package saml

import (
	"net/mail"
	"strings"
)

// Claim URIs the Microsoft providers (Entra ID, AD FS) send attributes under.
const (
	claimEmail       = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	claimGivenName   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
	claimSurname     = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
	claimName        = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	claimDisplayName = "http://schemas.microsoft.com/identity/claims/displayname"
)

// Mapping is which attributes the address and the name are read from. An
// empty attribute is not read.
type Mapping struct {
	Email, Name, GivenName, FamilyName string
}

// Profile is an identity provider's usual attribute names: what the admin
// page fills the mapping in with when that provider is picked.
type Profile struct {
	Name, Label string
	Mapping     Mapping
}

// The profiles, in the order the admin page offers them. Generic is the
// default.
const ProfileGeneric = "generic"

// Profiles is every profile. Whatever the profile, the address falls back
// to the subject's NameID when no attribute carries it and the NameID is an
// address, which is how Google Workspace, JumpCloud and Okta send it unless
// told otherwise.
var Profiles = []Profile{
	{Name: "okta", Label: "Okta", Mapping: Mapping{Email: "email", Name: "name", GivenName: "firstName", FamilyName: "lastName"}},
	{Name: "entra", Label: "Microsoft Entra ID", Mapping: Mapping{Email: claimEmail, Name: claimDisplayName, GivenName: claimGivenName, FamilyName: claimSurname}},
	{Name: "google", Label: "Google Workspace", Mapping: Mapping{Email: "email", Name: "name", GivenName: "firstName", FamilyName: "lastName"}},
	{Name: "jumpcloud", Label: "JumpCloud", Mapping: Mapping{Email: "email", Name: "name", GivenName: "firstname", FamilyName: "lastname"}},
	{Name: "adfs", Label: "AD FS", Mapping: Mapping{Email: claimEmail, Name: claimName, GivenName: claimGivenName, FamilyName: claimSurname}},
	{Name: "onelogin", Label: "OneLogin", Mapping: Mapping{Email: "User.email", Name: "name", GivenName: "User.FirstName", FamilyName: "User.LastName"}},
	{Name: ProfileGeneric, Label: "Other SAML 2.0 provider", Mapping: Mapping{Email: "email", Name: "name", GivenName: "firstName", FamilyName: "lastName"}},
}

// ProfileNamed is the profile called name.
func ProfileNamed(name string) (Profile, bool) {
	for _, p := range Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// transient is the NameID format that is a fresh value per sign-in.
const transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

// Resolve is the address and the display name an assertion gives under m:
// the address from its attribute, else the NameID when that is an address;
// the name from its attribute, else the given and family names, else empty.
// The address is not trusted for being here: the caller still requires it
// to be in the org's proven domain.
func (m Mapping) Resolve(a Assertion) (email, name string, err error) {
	first := func(attr string) string {
		if attr == "" {
			return ""
		}
		for _, v := range a.Attributes[attr] {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
		return ""
	}
	email = first(m.Email)
	if email == "" && a.NameIDFormat != transient {
		email = a.NameID
	}
	addr, perr := mail.ParseAddress(email)
	if email == "" || perr != nil || addr.Address != email || len(email) > 320 {
		return "", "", ErrNoAddress
	}
	name = first(m.Name)
	if name == "" {
		name = strings.TrimSpace(first(m.GivenName) + " " + first(m.FamilyName))
	}
	if r := []rune(name); len(r) > 200 {
		name = string(r[:200])
	}
	return email, name, nil
}

// Subject is the assertion's stable subject, for the person's record: the
// NameID, unless it is transient and so means nothing next time.
func (a Assertion) Subject() string {
	if a.NameIDFormat == transient || len(a.NameID) > 255 {
		return ""
	}
	return a.NameID
}
