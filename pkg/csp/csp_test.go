package csp_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/csp"
)

// What two bring-your-own providers would declare, as a product built on
// the template would; the shape is what matters here.
var (
	livekit = csp.Origins{Connect: []string{"wss://acme.livekit.cloud", "https://acme.livekit.cloud"}}
	ably    = csp.Origins{Connect: []string{"wss://realtime.ably.io", "https://rest.ably.io"}}
	frames  = csp.Origins{Frame: []string{"https://embed.example"}}
)

func base() csp.Policy {
	return csp.Base([]string{"https://api.b2bapp.example", "wss://live.b2bapp.example"}, []string{csp.ScriptHash("console.log(1)")})
}

func TestFreeOrgPolicyNamesNoProvider(t *testing.T) {
	p := csp.Assemble(base())
	s := p.String()
	for _, forbidden := range []string{"livekit", "ably", "daily", "agora"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("free org policy names %s: %s", forbidden, s)
		}
	}
	if !slices.Equal(p.Sources("connect-src"), []string{"'self'", "https://api.b2bapp.example", "wss://live.b2bapp.example"}) {
		t.Errorf("connect-src %v", p.Sources("connect-src"))
	}
}

func TestOrgWithProvidersGetsExactlyTheirOrigins(t *testing.T) {
	p := csp.Assemble(base(), livekit, ably)
	connect := p.Sources("connect-src")
	for _, o := range append(livekit.Connect, ably.Connect...) {
		if !slices.Contains(connect, o) {
			t.Errorf("connect-src lacks %s: %v", o, connect)
		}
	}
	if strings.Contains(p.String(), "daily") {
		t.Errorf("a provider the org did not configure appears: %s", p.String())
	}
	// Assembling for one org never changes the base another org starts from.
	if s := csp.Assemble(base()).String(); strings.Contains(s, "livekit") {
		t.Errorf("base policy was mutated: %s", s)
	}
}

func TestBaseIsStrict(t *testing.T) {
	p := base()
	script := p.Sources("script-src")
	if slices.Contains(script, "'unsafe-inline'") || slices.Contains(script, "'unsafe-eval'") {
		t.Errorf("script-src allows inline or eval: %v", script)
	}
	if !slices.ContainsFunc(script, func(s string) bool { return strings.HasPrefix(s, "'sha256-") }) {
		t.Errorf("the first-paint script must be allowed by hash: %v", script)
	}
	for directive, want := range map[string]string{
		"frame-ancestors": "'none'",
		"object-src":      "'none'",
		"base-uri":        "'self'",
		"form-action":     "'self'",
		"frame-src":       "'none'",
	} {
		if !slices.Equal(p.Sources(directive), []string{want}) {
			t.Errorf("%s = %v, want %s", directive, p.Sources(directive), want)
		}
	}
	if !strings.Contains(p.String(), "upgrade-insecure-requests") {
		t.Error("no upgrade-insecure-requests")
	}
}

func TestFrameSourcesReplaceNone(t *testing.T) {
	p := csp.Assemble(base(), frames)
	if !slices.Equal(p.Sources("frame-src"), []string{"https://embed.example"}) {
		t.Errorf("frame-src %v", p.Sources("frame-src"))
	}
}

func TestScriptHashMatchesTheBrowser(t *testing.T) {
	// The browser hashes the exact script text between the tags.
	if got := csp.ScriptHash("alert(1)"); got != "'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='" {
		t.Fatalf("got %s", got)
	}
}

// The one platform-wide runtime script, the CAPTCHA widget, is declared like
// a provider and lands in script-src and frame-src; the free org's policy
// without it names no external script.
func TestScriptOriginsAreDeclaredNotAssumed(t *testing.T) {
	widget := csp.Origins{Script: []string{"https://captcha.example/api/"}, Frame: []string{"https://captcha.example/"}}
	p := csp.Assemble(base(), widget)
	if !slices.Contains(p.Sources("script-src"), "https://captcha.example/api/") || !slices.Contains(p.Sources("frame-src"), "https://captcha.example/") {
		t.Errorf("widget origins missing: %s", p.String())
	}
	if s := csp.Assemble(base()).String(); strings.Contains(s, "captcha.example") {
		t.Errorf("script origin without a declarer: %s", s)
	}
}
