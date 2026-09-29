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

// Every Go service has its schema and role, and its contract.
func TestEveryServiceIsRegistered(t *testing.T) {
	for _, name := range goServices(t) {
		if _, ok := db.ServiceByName(name); !ok {
			t.Errorf("services/%s: add it to pkg/db.Services so it gets a schema and a role", name)
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
// product's name comes from config (pkg/config.Brand), and code names it
// nowhere.
var productWord = regexp.MustCompile(`(?i)unityofis|\bofis\b`)

// The product's name is configuration, never a literal. Tests may still use
// a made-up one.
func TestNoProductNameInCode(t *testing.T) {
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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(body), "\n") {
			if productWord.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d: names the product; read it from config instead", filepath.ToSlash(rel), i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
