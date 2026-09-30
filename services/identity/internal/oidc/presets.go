package oidc

// The presets an organization's provider is filled in from. A preset is a
// form, not a kind of provider: whatever it fills in, sign-in is the same
// OpenID Connect flow against the issuer it names.
const (
	PresetEntra   = "entra"
	PresetGoogle  = "google"
	PresetGeneric = "generic"
)

// Preset is what one preset fills in.
type Preset struct {
	Name string
	// Issuer is the issuer the preset uses: {tenant_id} stands for Entra's
	// tenant; empty for generic, which asks for it.
	Issuer string
	Scopes []string
	// The claims the address and name come from, and the claim read when
	// the address claim is absent.
	EmailClaim, NameClaim, EmailFallback string
	RequireEmailVerified                 bool
	// Fields is the inputs the preset asks for besides the client id and
	// secret.
	Fields []string
	// LooseIssuer lets the discovery document name a different issuer
	// from the one asked for, on the same host: Entra asked by verified
	// domain answers with the tenant's GUID, which is what its tokens carry.
	LooseIssuer bool
}

// Presets is every preset, in the order the admin page offers them.
var Presets = []Preset{
	{
		Name: PresetEntra, Issuer: EntraAuthority + "/{tenant_id}/v2.0",
		Scopes:     []string{"openid", "profile", "email"},
		EmailClaim: "email", NameClaim: "name",
		// Entra sends email only when the account has a mail attribute and
		// the app asks for it; the sign-in name is always there.
		EmailFallback: "preferred_username",
		Fields:        []string{"tenant_id"},
		LooseIssuer:   true,
	},
	{
		Name: PresetGoogle, Issuer: GoogleIssuer,
		Scopes:     []string{"openid", "email", "profile"},
		EmailClaim: "email", NameClaim: "name",
		// Google says whether it verified the address, and a consumer
		// account can carry a company address: hd proves Workspace.
		RequireEmailVerified: true,
		Fields:               []string{"hosted_domain"},
	},
	{
		Name:       PresetGeneric,
		Scopes:     []string{"openid", "email", "profile"},
		EmailClaim: "email", NameClaim: "name",
		Fields: []string{"issuer"},
	},
}

// PresetNamed is the preset called name.
func PresetNamed(name string) (Preset, bool) {
	for _, p := range Presets {
		if p.Name == name {
			return p, true
		}
	}
	return Preset{}, false
}
