// Package csp assembles the Content Security Policy for the web apps.
//
// The apps are served with a fixed base policy plus the origins each
// third-party integration in use declares: in the template, the CAPTCHA
// widget (pkg/captcha); in a product, any embed or SDK host one of its
// features adds, per org when only some orgs turn it on. Nothing else. An org
// that uses none gets no external origin at all, so a fixed policy naming
// every integration would be both too loose for that org and too tight for
// the one that needs it.
package csp

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"sort"
	"strings"
)

// Origins is what one integration needs the browser to be allowed to reach:
// exactly the origins its client code connects to.
type Origins struct {
	// Connect: API and socket endpoints (connect-src). wss:// origins go here.
	Connect []string
	// Media: where audio and video are fetched from (media-src).
	Media []string
	// Worker: origins workers are loaded from (worker-src).
	Worker []string
	// Frame: origins embedded in an iframe (frame-src). Rare, and a reason to
	// look twice at the integration.
	Frame []string
	// Script: origins a script is loaded from (script-src). Rarer still: an
	// SDK is bundled, never loaded at runtime. The CAPTCHA widget is the
	// template's one case.
	Script []string
}

// Declarer is an integration that declares its CSP origins (the CAPTCHA
// verifier is one).
type Declarer interface {
	CSPOrigins() Origins
}

// Policy is a set of directives.
type Policy struct {
	directives map[string][]string
}

// Base is the policy every web app starts from. selfOrigins are the product's
// own hosts a page must reach beyond itself, such as the API host.
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

// Assemble is base plus the origins of every integration in use. Passing none
// returns base unchanged.
func Assemble(base Policy, integrations ...Origins) Policy {
	p := base.clone()
	for _, o := range integrations {
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
