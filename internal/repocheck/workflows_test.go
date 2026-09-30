package repocheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The GitHub Actions workflows are safe to run on a public repository that
// anyone can fork and open a pull request against:
//
//   - Every workflow defaults to read-only: a top-level permissions of
//     contents: read and nothing more. A job that needs more asks for it.
//   - No pull_request_target workflow checks out code: that trigger runs with
//     the base repository's secrets and a write token, so running the pull
//     request's code there hands both to whoever opened it.
//   - A job that uses a secret (other than the run's own GITHUB_TOKEN) or a
//     deployment environment runs only on the upstream repository, and only
//     from main or a tag. A fork, or a pull request, skips it.
//
// So build, test, lint and the drift check never need a secret, and pass on
// a fork's pull request. A product that forks the template changes upstream
// to its own repository.

// upstream is the one repository a job with a secret may run on.
const upstream = "UnityEvolv/b2b-backend-template"

// expression is a ${{ ... }} expression: only inside one is secrets.X a
// secret; in a shell line, secrets.md is a file name.
var (
	expression = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
	// Not needs.secrets.result: that is a job named secrets.
	secretName = regexp.MustCompile(`(?:^|[^.\w])secrets\.(\w+)`)
)

// usesSecret is whether text names a secret other than GITHUB_TOKEN in an
// expression.
func usesSecret(text string) bool {
	for _, expr := range expression.FindAllString(text, -1) {
		for _, m := range secretName.FindAllStringSubmatch(expr, -1) {
			if m[1] != "GITHUB_TOKEN" {
				return true
			}
		}
	}
	return false
}

// events is the event names a workflow's on lists, whatever its shape.
func events(on any) []string {
	switch v := on.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		var out []string
		for k := range v {
			out = append(out, k)
		}
		return out
	}
	return nil
}

var (
	guardRef   = `(?:github\.ref == 'refs/heads/main'|startsWith\(github\.ref, 'refs/tags/'\))`
	guardShape = regexp.MustCompile(`^github\.repository == '` + regexp.QuoteMeta(upstream) + `' && (?:` + guardRef + `|\(` + guardRef + `(?: \|\| ` + guardRef + `)*\))(?: && (.+))?$`)
	whitespace = regexp.MustCompile(`\s+`)
)

// guarded is whether a job's if keeps it to the upstream repository and to
// main or a tag: the upstream check first, then main or a tag, then
// anything else only joined by &&. An || outside the parentheses would let a
// fork through.
func guarded(condition string) bool {
	text := strings.TrimSpace(condition)
	text = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "${{"), "}}"))
	text = whitespace.ReplaceAllString(text, " ")
	m := guardShape.FindStringSubmatch(text)
	return m != nil && !strings.Contains(m[1], "||")
}

// asText is v as JSON, for looking for secrets in it.
func asText(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// checkWorkflow is the problems with one parsed workflow, as sentences.
func checkWorkflow(name string, w map[string]any) []string {
	var problems []string
	perms, _ := w["permissions"].(map[string]any)
	if len(perms) != 1 || perms["contents"] != "read" {
		problems = append(problems, name+": the top-level permissions must be exactly `contents: read`.")
	}
	if usesSecret(asText(w["env"])) {
		problems = append(problems, name+": a secret in the workflow-level env reaches every job; give it to the one job that needs it.")
	}
	target := false
	for _, e := range events(w["on"]) {
		target = target || e == "pull_request_target"
	}
	jobs, _ := w["jobs"].(map[string]any)
	for id, raw := range jobs {
		job, _ := raw.(map[string]any)
		steps, _ := job["steps"].([]any)
		if target {
			for _, s := range steps {
				step, _ := s.(map[string]any)
				if uses, _ := step["uses"].(string); strings.HasPrefix(uses, "actions/checkout") {
					problems = append(problems, name+": job "+id+" checks out code under pull_request_target, which runs it with the base repository's secrets.")
					break
				}
			}
		}
		condition, _ := job["if"].(string)
		inherits := job["secrets"] == "inherit"
		if (usesSecret(asText(job)) || inherits || job["environment"] != nil) && !guarded(condition) {
			problems = append(problems, name+": job "+id+" uses a secret or an environment, so its `if` must require "+
				"github.repository == '"+upstream+"' and github.ref == 'refs/heads/main' or startsWith(github.ref, 'refs/tags/').")
		}
	}
	return problems
}

// Every workflow in .github/workflows is safe to run on forks.
func TestWorkflowsAreForkSafe(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.y*ml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no workflows found")
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var w map[string]any
		if err := yaml.Unmarshal(body, &w); err != nil {
			t.Fatalf("%s: %v", filepath.Base(file), err)
		}
		for _, p := range checkWorkflow(".github/workflows/"+filepath.Base(file), w) {
			t.Error(p)
		}
	}
}

func TestGuardedKeepsSecretsOnUpstreamMainOrTags(t *testing.T) {
	guard := "github.repository == '" + upstream + "' && github.ref == 'refs/heads/main'"
	for _, ok := range []string{
		guard,
		"${{ " + guard + " }}",
		"github.repository == '" + upstream + "' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')) && !cancelled()",
	} {
		if !guarded(ok) {
			t.Errorf("refused: %s", ok)
		}
	}
	for _, bad := range []string{
		"",
		"github.ref == 'refs/heads/main'",
		"github.repository == '" + upstream + "'",
		"github.repository == 'someone/fork' && github.ref == 'refs/heads/main'",
		guard + " || github.event_name == 'workflow_dispatch'",
	} {
		if guarded(bad) {
			t.Errorf("passed: %s", bad)
		}
	}
}

func TestCheckWorkflowCatchesWhatIsNotForkSafe(t *testing.T) {
	parse := func(src string) map[string]any {
		t.Helper()
		var w map[string]any
		if err := yaml.Unmarshal([]byte(src), &w); err != nil {
			t.Fatal(err)
		}
		return w
	}
	cases := []struct {
		name     string
		src      string
		problems int
	}{
		{"read-only, no secret", "on: pull_request\npermissions: {contents: read}\njobs:\n  a:\n    steps: [{run: go test ./...}]\n", 0},
		{"no permissions", "on: push\njobs: {}\n", 1},
		{"write permissions", "on: push\npermissions: {contents: write}\njobs: {}\n", 1},
		{"write-all", "on: push\npermissions: write-all\njobs: {}\n", 1},
		{"checkout under pull_request_target", "on: [pull_request_target]\npermissions: {contents: read}\njobs:\n  label:\n    steps: [{uses: actions/checkout@v7}]\n", 1},
		{"unguarded secret", "on: push\npermissions: {contents: read}\njobs:\n  deploy:\n    steps: [{run: deploy, env: {TOKEN: '${{ secrets.DEPLOY_TOKEN }}'}}]\n", 1},
		{"guarded secret", "on: push\npermissions: {contents: read}\njobs:\n  deploy:\n    if: github.repository == '" + upstream + "' && github.ref == 'refs/heads/main'\n    steps: [{run: deploy, env: {TOKEN: '${{ secrets.DEPLOY_TOKEN }}'}}]\n", 0},
		{"unguarded environment", "on: push\npermissions: {contents: read}\njobs:\n  release:\n    environment: production\n    steps: []\n", 1},
		{"inherited secrets", "on: push\npermissions: {contents: read}\njobs:\n  call:\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n", 1},
		{"the run's own token", "on: push\npermissions: {contents: read}\njobs:\n  gh:\n    steps: [{run: gh, env: {GH_TOKEN: '${{ secrets.GITHUB_TOKEN }}'}}]\n", 0},
		{"a file named secrets.md", "on: push\npermissions: {contents: read}\njobs:\n  a:\n    steps: [{run: cat secrets.md}]\n", 0},
		{"another job named secrets", "on: push\npermissions: {contents: read}\njobs:\n  b:\n    steps: [{run: echo, env: {R: '${{ needs.secrets.result }}'}}]\n", 0},
		{"a secret for every job", "on: push\npermissions: {contents: read}\nenv: {KEY: '${{ secrets.KEY }}'}\njobs: {}\n", 1},
	}
	for _, c := range cases {
		if got := checkWorkflow("a.yml", parse(c.src)); len(got) != c.problems {
			t.Errorf("%s: %d problems, want %d: %v", c.name, len(got), c.problems, got)
		}
	}
}
