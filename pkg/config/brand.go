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
