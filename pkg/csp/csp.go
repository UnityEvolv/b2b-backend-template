// Package csp assembles the Content Security Policy for the web apps.
//
// The apps are served with a fixed base policy plus, per org, the origins each
// provider plugin the org has configured declares. Nothing else. A free org on
// the built-in providers gets no external origin at all, so a fixed policy
// that named every provider would be both too loose for the free org and too
// tight for the org that needs one.
package csp

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"sort"
	"strings"
)

// Origins is what one provider needs the browser to be allowed to reach. A
// provider plugin declares exactly the origins its client adapter connects to.
type Origins struct {
	// Connect: API and socket endpoints (connect-src). wss:// origins go here.
	Connect []string
	// Media: where audio and video are fetched from (media-src), for providers
	// that serve recordings or streams over HTTP.
	Media []string
	// Worker: origins a provider loads workers from (worker-src).
	Worker []string
	// Frame: origins a provider embeds in an iframe (frame-src). Rare, and a
	// reason to look twice at the provider.
	Frame []string
	// Script: origins a provider loads a script from (script-src). Rarer
	// still: an RTC or messaging SDK is bundled, never loaded at runtime.
	// The CAPTCHA widget is the one platform-wide case.
	Script []string
}

// Declarer is a provider plugin that declares its CSP origins.
type Declarer interface {
	CSPOrigins() Origins
}

// Policy is a set of directives.
type Policy struct {
	directives map[string][]string
}

// Base is the policy every web app starts from. selfOrigins are the product's
// own hosts a page must reach beyond itself: the API and the realtime socket.
// scriptHashes allows the named inline scripts (the first-paint theme script)
// without allowing inline scripts in general.
func Base(selfOrigins []string, scriptHashes []string) Policy {
	p := Policy{directives: map[string][]string{}}
	p.set("default-src", "'self'")
	p.set("base-uri", "'self'")
	p.set("form-action", "'self'")
	p.set("frame-ancestors", "'none'")
	p.set("object-src", "'none'")
	p.set("script-src", append([]string{"'self'"}, scriptHashes...)...)
	// React sets style attributes for layout; that is style-src-attr, kept
	// separate so stylesheets stay 'self' only.
	p.set("style-src", "'self'")
	p.set("style-src-attr", "'unsafe-inline'")
	p.set("img-src", "'self'", "data:", "blob:")
	p.set("font-src", "'self'")
	p.set("media-src", "'self'", "blob:")
	p.set("worker-src", "'self'", "blob:")
	p.set("connect-src", append([]string{"'self'"}, selfOrigins...)...)
	p.set("frame-src", "'none'")
	p.set("upgrade-insecure-requests")
	return p
}

// Assemble is base plus the origins of every provider the org has configured.
// Passing no providers returns base unchanged: the free org's policy.
func Assemble(base Policy, providers ...Origins) Policy {
	p := base.clone()
	for _, o := range providers {
		p.add("connect-src", o.Connect...)
		p.add("media-src", o.Media...)
		p.add("worker-src", o.Worker...)
		p.add("script-src", o.Script...)
		if len(o.Frame) > 0 {
			// 'none' cannot sit beside an origin.
			p.directives["frame-src"] = slices.DeleteFunc(p.directives["frame-src"], func(s string) bool { return s == "'none'" })
			p.add("frame-src", o.Frame...)
		}
	}
	return p
}

// Sources is what a directive allows, for tests and for the report.
func (p Policy) Sources(directive string) []string {
	return slices.Clone(p.directives[directive])
}

// String is the header value.
func (p Policy) String() string {
	names := make([]string, 0, len(p.directives))
	for name := range p.directives {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if sources := p.directives[name]; len(sources) > 0 {
			parts = append(parts, name+" "+strings.Join(sources, " "))
		} else {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "; ")
}

// Header names. Report-only is used first on a new app, to find what a policy
// would break before it is enforced.
const (
	Header           = "Content-Security-Policy"
	HeaderReportOnly = "Content-Security-Policy-Report-Only"
)

// ScriptHash is the source expression that allows one exact inline script.
func ScriptHash(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func (p *Policy) set(directive string, sources ...string) {
	p.directives[directive] = slices.Clone(sources)
}

func (p *Policy) add(directive string, sources ...string) {
	for _, s := range sources {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(p.directives[directive], s) {
			p.directives[directive] = append(p.directives[directive], s)
		}
	}
}

func (p Policy) clone() Policy {
	c := Policy{directives: make(map[string][]string, len(p.directives))}
	for k, v := range p.directives {
		c.directives[k] = slices.Clone(v)
	}
	return c
}
