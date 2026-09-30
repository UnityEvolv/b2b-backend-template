// Package repocheck holds the rules that span the whole repository, checked on
// every build: how services relate to each other, and what their queries must
// look like. None of it needs a database.
package repocheck

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

const module = "github.com/UnityEvolv/b2b-backend-template"

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// Go service directories: those with a main.go.
func goServices(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(repoRoot(t), "services", "*", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range matches {
		names = append(names, filepath.Base(filepath.Dir(m)))
	}
	return names
}

// Services import pkg/. They never import each other: a service that needs
// another's data calls its API.
func TestServicesDoNotImportEachOther(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-json", "./services/...")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	// go list -deps prints each package once; for every package inside a
	// service, collect the imports that land in a different service.
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	for decoder.More() {
		var pkg struct {
			ImportPath string
			Imports    []string
		}
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		own := serviceOf(pkg.ImportPath)
		if own == "" {
			continue
		}
		for _, imp := range pkg.Imports {
			if other := serviceOf(imp); other != "" && other != own {
				t.Errorf("%s imports %s: services never import each other; call its API", pkg.ImportPath, imp)
			}
		}
	}
}

func serviceOf(importPath string) string {
	rest, ok := strings.CutPrefix(importPath, module+"/services/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	return name
}

// Every Go service has its schema and role, and its contract. The
// template's are in pkg/db.Default; a product's registers itself in its own
// main.
func TestEveryServiceIsRegistered(t *testing.T) {
	for _, name := range goServices(t) {
		main, _ := os.ReadFile(filepath.Join(repoRoot(t), "services", name, "main.go"))
		if _, ok := db.ServiceByName(name); !ok && !strings.Contains(string(main), "db.Default.Register(") {
			t.Errorf("services/%s: register it with db.Default.Register in its main so it gets a schema and a role", name)
		}
		if _, err := os.Stat(filepath.Join(repoRoot(t), "api", name+".yaml")); err != nil {
			t.Errorf("services/%s: no api/%s.yaml; the contract comes first", name, name)
		}
	}
}

var queryName = regexp.MustCompile(`(?m)^-- name: (\w+)`)

// Every query names org_id: it routes the shard and leads every index. A query
// that is genuinely not per-org says so with a "-- global: <reason>" line.
func TestQueriesAreOrgScoped(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "services", "*", "queries", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		starts := queryName.FindAllStringSubmatchIndex(text, -1)
		for i, s := range starts {
			end := len(text)
			if i+1 < len(starts) {
				end = starts[i+1][0]
			}
			query, name := text[s[0]:end], text[s[2]:s[3]]
			if !strings.Contains(query, "org_id") && !strings.Contains(query, "-- global:") {
				rel, _ := filepath.Rel(repoRoot(t), file)
				t.Errorf("%s: %s does not name org_id; scope it to an org or mark it -- global: <reason>", filepath.ToSlash(rel), name)
			}
		}
	}
}

// productWord is a name of the product this template was carved from, or
// the product word "ofis" on its own. Neither belongs in the template: the
// product's name comes from config (pkg/config.Brand), and nothing names it.
var productWord = regexp.MustCompile(`(?i)unity` + `ofis|\bofis\b`)

// shipped is whether path is a file the template ships as text: code,
// queries, contracts, scripts, deploy files and docs.
func shipped(path string) bool {
	switch filepath.Ext(path) {
	case ".go", ".sql", ".yaml", ".yml", ".sh", ".md", ".lua", ".py", ".json", ".tmpl", ".html", ".txt":
		return true
	}
	return strings.HasSuffix(path, "Dockerfile")
}

// walkShipped calls fn with every line of every shipped file under the
// repository root, by its slash-separated path from the root.
func walkShipped(t *testing.T, fn func(rel string, n int, line string)) {
	t.Helper()
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !shipped(path) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(body), "\n") {
			fn(rel, i+1, line)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The product's name is configuration, never a literal: not in code, tests,
// queries, contracts, deploy files or docs. This package, which spells the
// rule out, is the one exception.
func TestNoProductNameInCode(t *testing.T) {
	walkShipped(t, func(rel string, n int, line string) {
		if !strings.HasPrefix(rel, "internal/repocheck/") && productWord.MatchString(line) {
			t.Errorf("%s:%d: names the product; read it from config instead", rel, n)
		}
	})
}

// brandRule is one literal that must stay configuration: what it is, the
// pattern that finds it, and the one spelling allowed, when there is one.
type brandRule struct {
	what   string
	re     *regexp.Regexp
	except *regexp.Regexp
}

func (r brandRule) caught(line string) bool {
	return r.re.MatchString(line) && (r.except == nil || !r.except.MatchString(line))
}

// brandLiterals are the strings a product shows its users or stamps on
// shared infrastructure, each of which comes from config (pkg/config.Brand,
// Redis, AppsFrom) derived from the product's name and base hostname. Any
// of them spelled out in Go outside pkg/config is a product name hardcoded
// again, whatever the name.
var brandLiterals = []brandRule{
	{"the template's default product id or name; use config.Brand", regexp.MustCompile(`(?i)b2bapp|"B2B App"`), nil},
	{"a Redis channel or key under a fixed prefix; use config.Redis", regexp.MustCompile(`"[^"\s]*:(notify|to-members|live-events|focus)\b`), nil},
	{"a fixed domain verification record; use DOMAIN_TXT_PREFIX and DOMAIN_TXT_VALUE_PREFIX", regexp.MustCompile(`"_?[A-Za-z0-9]+[A-Za-z0-9-]*-verify[.=]`), nil},
	{"a fixed token audience or desktop URL scheme; default them to the product id", regexp.MustCompile(`"(AUTH_AUDIENCE|DESKTOP_SCHEME)",\s*"`), nil},
	{"a fixed TOTP issuer; use the product name", regexp.MustCompile(`totp\.URI\([^,]+,\s*"`), nil},
	{"a fixed Stripe metadata source; use the product id", regexp.MustCompile(`metadata\[source\]":\s*\{"`), nil},
	{"a MIME boundary that names something; keep it neutral", regexp.MustCompile(`boundary\s*:?=\s*"`), regexp.MustCompile(`boundary\s*:?=\s*"part-"`)},
	{"an advisory lock named for a product; name the job", regexp.MustCompile(`pg_advisory_(un)?lock\(hashtext\('[^'.]*(ofis|unity|b2b)`), nil},
	{"the realtime or TURN subdomain; a product declares its own app origins", regexp.MustCompile(`Subdomain(Realtime|TURN)\b|"(rt|turn)\."`), nil},
	{"a fixed session or sign-in cookie name; use config.Cookies (COOKIE_PREFIX)", regexp.MustCompile(`"[A-Za-z0-9-]*_(session|signin)"`), nil},
	{"a fixed SCIM token prefix; use config.SCIMTokenPrefixFrom (SCIM_TOKEN_PREFIX)", regexp.MustCompile(`"[A-Za-z0-9-]+_?scim_`), nil},
	{"a fixed web app name; APP_NAMES names them and config.DefaultApps is the default", regexp.MustCompile(`(MainApp|PlatformApp|DefaultApps)\s*(:|=|:=)\s*(\[\]string\{)?"[a-z]`), nil},
}

// B2B-19's audit items stay configuration: this fails when one of them is
// written as a literal again.
func TestBrandingComesFromConfig(t *testing.T) {
	walkShipped(t, func(rel string, n int, line string) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "pkg/config/") {
			return
		}
		for _, l := range brandLiterals {
			if l.caught(line) {
				t.Errorf("%s:%d: %s", rel, n, l.what)
			}
		}
	})
}

// The rules above catch what they are meant to: each of these is how the
// literal looked in the product the template was carved from, or would
// look hardcoded under the template's own name.
func TestBrandingRulesCatchTheOldLiterals(t *testing.T) {
	old := []string{
		`const Channel = "acme:live-events"`,
		`func FocusKey(org, to uuid.UUID) string { return fmt.Sprintf("acme:focus:%s:%s", org, to) }`,
		`TXTPrefix: env.String("DOMAIN_TXT_PREFIX", "_acme-verify."),`,
		`TXTValuePrefix: "acme-verify=",`,
		`audience = env.String("AUTH_AUDIENCE", "acme")`,
		`desktopScheme = env.String("DESKTOP_SCHEME", "acme")`,
		`OtpauthUri: totp.URI(secret, "acme", account.Email)`,
		`"metadata[source]": {"acme"},`,
		`boundary := "acme-" + strings.ReplaceAll(id, "@", "-")`,
		`admin.Exec(ctx, "SELECT pg_advisory_lock(hashtext('b2bapp.dbinit'))")`,
		`SubdomainRealtime = "rt"`,
		`source: "b2bapp",`,
		`sessionCookie = "uo_session"`,
		`attemptCookie = "uo_signin"`,
		`scimTokenPrefix = "uoscim_"`,
		`cfg.MainApp = "office"`,
		`MainApp: "office",`,
	}
	for _, line := range old {
		caught := false
		for _, l := range brandLiterals {
			caught = caught || l.caught(line)
		}
		if !caught {
			t.Errorf("not caught: %s", line)
		}
	}
	for _, line := range []string{
		`boundary := "part-" + strings.ReplaceAll(id, "@", "-")`,
		`admin.Exec(ctx, "SELECT pg_advisory_lock(hashtext('db.bootstrap'))")`,
		`TXTPrefix: env.String("DOMAIN_TXT_PREFIX", "_"+brand.ID+"-verify."),`,
		`audience = env.String("AUTH_AUDIENCE", brand.ID)`,
		`cookieNames = config.CookiesFor(prefix)`,
		`prefix := s.scimTokenPrefix()`,
		`cfg.MainApp = config.DefaultApps[0]`,
		`s.notifyAdmins(ctx, org, "scim-cap:"+day, "scim_cap_reached", data)`,
	} {
		for _, l := range brandLiterals {
			if l.caught(line) {
				t.Errorf("config-derived line caught as %q: %s", l.what, line)
			}
		}
	}
}
