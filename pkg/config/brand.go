package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Brand is how the product names itself. Nothing in the code names it:
// every email, token audience, URL scheme and Redis key comes from here.
type Brand struct {
	// Name is what people read: "Sent by <Name>", the authenticator's label.
	Name string
	// ID is what machines read: lower case letters, digits and hyphens. It is
	// the default token audience, the desktop app's URL scheme and the Redis
	// prefix.
	ID string
}

// DefaultBrand is the template's own name, for a product that sets none.
var DefaultBrand = Brand{Name: "B2B App", ID: "b2bapp"}

// TXTPrefix is the default name of the DNS record that proves a domain,
// before the domain: "_<id>-verify.".
func (b Brand) TXTPrefix() string { return "_" + b.ID + "-verify." }

// TXTValuePrefix is the default start of that record's value, before the
// token: "<id>-verify=".
func (b Brand) TXTValuePrefix() string { return b.ID + "-verify=" }

var brandID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// BrandFrom reads PRODUCT_NAME and PRODUCT_ID, each defaulting to
// DefaultBrand's.
func BrandFrom(e *Env) Brand {
	b := Brand{
		Name: e.String("PRODUCT_NAME", DefaultBrand.Name),
		ID:   e.String("PRODUCT_ID", DefaultBrand.ID),
	}
	if !brandID.MatchString(b.ID) {
		e.problems = append(e.problems, fmt.Sprintf("PRODUCT_ID: %q is not lower case letters, digits and hyphens", b.ID))
		b.ID = DefaultBrand.ID
	}
	return b
}

// Redis is the Redis channels and keys the services agree on, under one
// prefix, so two products sharing a Redis never hear each other.
type Redis struct {
	Prefix string
}

// DefaultRedis is the names under the default brand.
var DefaultRedis = Redis{Prefix: DefaultBrand.ID}

// RedisFrom reads REDIS_PREFIX, the brand's id when unset.
func RedisFrom(e *Env, b Brand) Redis {
	return Redis{Prefix: e.String("REDIS_PREFIX", b.ID)}
}

// Key is the prefix and parts joined with colons.
func (r Redis) Key(parts ...string) string {
	return r.Prefix + ":" + strings.Join(parts, ":")
}

// Notify is the channel services hand notification events to.
func (r Redis) Notify() string { return r.Key("notify") }

// LiveEvents is the live-session event bus (pkg/livebus): things pushed to
// the people who have the product open, such as a session ending.
func (r Redis) LiveEvents() string { return r.Key("live-events") }

// ToMembers is the channel per-person live events go out on.
func (r Redis) ToMembers() string { return r.Key("to-members") }

// Cookies is the names of the cookies the identity service sets on the API
// host: the session's refresh token, and the sign-in attempt that binds an
// identity provider's callback to the browser that started it.
type Cookies struct {
	Session string
	SignIn  string
}

// cookiePrefix is what a cookie name may start with: letters, digits,
// hyphens and underscores.
var cookiePrefix = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// CookiesFor is the cookie names under prefix: "<prefix>_session" and
// "<prefix>_signin", with any hyphen in the prefix as an underscore.
func CookiesFor(prefix string) Cookies {
	p := strings.ReplaceAll(prefix, "-", "_")
	return Cookies{Session: p + "_session", SignIn: p + "_signin"}
}

// DefaultCookies is the cookie names under the default brand.
var DefaultCookies = CookiesFor(DefaultBrand.ID)

// CookiesFrom reads COOKIE_PREFIX, the brand's id when unset.
func CookiesFrom(e *Env, b Brand) Cookies {
	prefix := e.String("COOKIE_PREFIX", b.ID)
	if !cookiePrefix.MatchString(prefix) {
		e.problems = append(e.problems, fmt.Sprintf("COOKIE_PREFIX: %q is not letters, digits, hyphens and underscores", prefix))
		prefix = b.ID
	}
	return CookiesFor(prefix)
}

// SCIMTokenPrefixFor is the start of every SCIM bearer token minted under
// the brand id: "<id>_scim_", with any hyphen as an underscore, so a secret
// scanner, or a person, can tell what a leaked one is.
func SCIMTokenPrefixFor(id string) string { return strings.ReplaceAll(id, "-", "_") + "_scim_" }

// DefaultSCIMTokenPrefix is the SCIM token prefix under the default brand.
var DefaultSCIMTokenPrefix = SCIMTokenPrefixFor(DefaultBrand.ID)

// SCIMTokenPrefixFrom reads SCIM_TOKEN_PREFIX, "<id>_scim_" when unset.
func SCIMTokenPrefixFrom(e *Env, b Brand) string {
	prefix := e.String("SCIM_TOKEN_PREFIX", SCIMTokenPrefixFor(b.ID))
	if !cookiePrefix.MatchString(prefix) {
		e.problems = append(e.problems, fmt.Sprintf("SCIM_TOKEN_PREFIX: %q is not letters, digits, hyphens and underscores", prefix))
		prefix = SCIMTokenPrefixFor(b.ID)
	}
	return prefix
}

// KeyPrefixes is the start of every API key and personal access token the
// identity service mints, so a secret scanner, or a person, can tell what a
// leaked one is and which kind.
type KeyPrefixes struct {
	Org      string
	Personal string
}

// KeyPrefixesFor is the prefixes under the brand id: "<id>_ak_" for an
// org's API key and "<id>_pat_" for a personal access token, with any
// hyphen as an underscore.
func KeyPrefixesFor(id string) KeyPrefixes {
	p := strings.ReplaceAll(id, "-", "_")
	return KeyPrefixes{Org: p + "_ak_", Personal: p + "_pat_"}
}

// DefaultKeyPrefixes is the key prefixes under the default brand.
var DefaultKeyPrefixes = KeyPrefixesFor(DefaultBrand.ID)

// KeyPrefixesFrom reads API_KEY_PREFIX and PAT_PREFIX, the brand's when
// unset. The two must differ.
func KeyPrefixesFrom(e *Env, b Brand) KeyPrefixes {
	def := KeyPrefixesFor(b.ID)
	out := KeyPrefixes{Org: e.String("API_KEY_PREFIX", def.Org), Personal: e.String("PAT_PREFIX", def.Personal)}
	for name, p := range map[string]*string{"API_KEY_PREFIX": &out.Org, "PAT_PREFIX": &out.Personal} {
		if !cookiePrefix.MatchString(*p) {
			e.problems = append(e.problems, fmt.Sprintf("%s: %q is not letters, digits, hyphens and underscores", name, *p))
		}
	}
	if out.Org == out.Personal {
		e.problems = append(e.problems, "API_KEY_PREFIX and PAT_PREFIX are the same")
	}
	return out
}
