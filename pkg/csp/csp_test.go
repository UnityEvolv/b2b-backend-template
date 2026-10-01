package csp_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/csp"
)

// What two integrations a product adds would declare; the shape is what
// matters here.
var (
	media  = csp.Origins{Connect: []string{"wss://media.vendor-one.example", "https://media.vendor-one.example"}}
	chat   = csp.Origins{Connect: []string{"wss://socket.vendor-two.example", "https://api.vendor-two.example"}}
	frames = csp.Origins{Frame: []string{"https://embed.example"}}
)

func base() csp.Policy {
	return csp.Base([]string{"https://api.b2bapp.example", "wss://live.b2bapp.example"}, []string{csp.ScriptHash("console.log(1)")})
}

func TestPolicyWithoutIntegrationsNamesNone(t *testing.T) {
	p := csp.Assemble(base())
	s := p.String()
	for _, forbidden := range []string{"vendor-one", "vendor-two", "vendor-three"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("policy names %s: %s", forbidden, s)
		}
	}
	if !slices.Equal(p.Sources("connect-src"), []string{"'self'", "https://api.b2bapp.example", "wss://live.b2bapp.example"}) {
		t.Errorf("connect-src %v", p.Sources("connect-src"))
	}
}

func TestIntegrationsGetExactlyTheirOrigins(t *testing.T) {
	p := csp.Assemble(base(), media, chat)
	connect := p.Sources("connect-src")
	for _, o := range append(media.Connect, chat.Connect...) {
		if !slices.Contains(connect, o) {
			t.Errorf("connect-src lacks %s: %v", o, connect)
		}
	}
	if strings.Contains(p.String(), "vendor-three") {
		t.Errorf("an integration not in use appears: %s", p.String())
	}
	// Assembling for one org never changes the base another org starts from.
	if s := csp.Assemble(base()).String(); strings.Contains(s, "vendor-one") {
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

// The template's one runtime script, the CAPTCHA widget, is declared like
// any integration and lands in script-src and frame-src; the policy without
// it names no external script.
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
