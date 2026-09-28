package migrations_test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

var fileName = regexp.MustCompile(`^\d{5}_[a-z0-9_]+\.sql$`)

// The shape every migration file must have, checked without a database.
func TestMigrationFiles(t *testing.T) {
	schemas := map[string]bool{}
	for _, s := range db.Services {
		schemas[s.Schema] = true
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		if !schemas[dir.Name()] {
			t.Errorf("%s/: not a service schema; directories are named after pkg/db.Services", dir.Name())
			continue
		}
		files, err := fs.ReadDir(migrations.FS, dir.Name())
		if err != nil {
			t.Fatal(err)
		}
		versions := map[string]string{}
		for _, f := range files {
			path := dir.Name() + "/" + f.Name()
			if !fileName.MatchString(f.Name()) {
				t.Errorf("%s: name must be NNNNN_snake_case.sql", path)
				continue
			}
			version := f.Name()[:5]
			if earlier, ok := versions[version]; ok {
				t.Errorf("%s: version %s already used by %s", path, version, earlier)
			}
			versions[version] = f.Name()

			body, err := fs.ReadFile(migrations.FS, path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(body)
			if !strings.Contains(text, "-- +goose Up") || !strings.Contains(text, "-- +goose Down") {
				t.Errorf("%s: needs both -- +goose Up and -- +goose Down", path)
			}
			// Unqualified names land in the service's own schema through
			// search_path; naming another schema is always a mistake. Comments
			// are not code: an example action like organization.plan.changed
			// in a comment reaches nothing.
			code := withoutComments(text)
			for other := range schemas {
				if other != dir.Name() && strings.Contains(code, other+".") {
					t.Errorf("%s: refers to %s., another service's schema", path, other)
				}
			}
		}
	}
}

// withoutComments is the SQL with every `--` comment removed. goose's own
// `-- +goose` annotations go too, which is fine: they name no schema.
func withoutComments(sql string) string {
	var out []string
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
