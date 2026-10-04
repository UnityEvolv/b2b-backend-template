// Package db is the database plumbing every service shares.
package db

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"sync"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
)

// Service is one service that owns one Postgres schema.
//
// One schema per service, one login role per service, and the role can reach
// its own schema and nothing else. A service that needs another's data calls
// its API; the database refuses the shortcut.
type Service struct {
	// Name is the service's name: its directory under services/ for the
	// template's own, and the name its service tokens carry.
	Name string
	// Schema is the Postgres schema it owns. Usually the same as Name; `users`
	// rather than `user`, because `user` is a reserved word in Postgres.
	Schema string
	// Migrations is the service's migration files, 00001_baseline.sql and on,
	// at the root. Nil while it has none: the schema is reserved for a
	// service still to be built.
	Migrations fs.FS
}

// Role is the login role the service connects as. It owns the schema, so the
// service runs its own migrations, and it has no privileges anywhere else.
func (s Service) Role() string { return "svc_" + s.Schema }

// Registry is the services that own a schema: the template's and the ones a
// product registers. Being registered is what gives a service a schema and a
// role (Bootstrap) and runs its migrations. Safe for concurrent use;
// registration is expected at start, before anything is bootstrapped.
type Registry struct {
	mu       sync.RWMutex
	services []Service
}

// schemaName is what a schema may be called: lower case, a letter first, so
// it needs no quoting and its role name and password variable follow from it.
var schemaName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,50}$`)

// New is a registry with the template's own services, each with its
// directory in migrations/.
func New() *Registry {
	r := &Registry{}
	for _, s := range []Service{
		{Name: "organization", Schema: "organization"},
		{Name: "identity", Schema: "identity"},
		{Name: "user", Schema: "users"},
		{Name: "authorization", Schema: "authz"},
		{Name: "audit", Schema: "audit"},
		{Name: "notification", Schema: "notification"},
		{Name: "billing", Schema: "billing"},
		{Name: "webhooks", Schema: "webhooks"},
	} {
		s.Migrations = Dir(migrations.FS, s.Schema)
		r.Register(s)
	}
	return r
}

// Default is the registry the package functions, the dbinit and migrate
// commands and every service read. A product adds its services at start;
// the template's own are in it until then.
var Default = New()

// Dir is dir inside fsys, or nil when it has no migration in it: for a
// Service's Migrations from an embedded tree of one directory per schema.
func Dir(fsys fs.FS, dir string) fs.FS {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			sub, err := fs.Sub(fsys, dir)
			if err != nil {
				return nil
			}
			return sub
		}
	}
	return nil
}

// Register adds a service. A name or schema that is empty or already
// taken, a schema that is not a plain lower-case name, or one Postgres
// keeps for itself panics: it is a programming error at start, not a
// request.
func (r *Registry) Register(s Service) {
	if s.Name == "" || !schemaName.MatchString(s.Schema) || s.Schema == "public" || strings.HasPrefix(s.Schema, "pg_") {
		panic(fmt.Sprintf("db: service %q with schema %q cannot be registered", s.Name, s.Schema))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.services {
		if x.Name == s.Name || x.Schema == s.Schema {
			panic(fmt.Sprintf("db: service %q or schema %q is already registered", s.Name, s.Schema))
		}
	}
	r.services = append(r.services, s)
}

// Services is every registered service, in registration order.
func (r *Registry) Services() []Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Service(nil), r.services...)
}

// ServiceByName finds a registered service by its name.
func (r *Registry) ServiceByName(name string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

// Services is every service in Default.
func Services() []Service { return Default.Services() }

// ServiceByName finds a service in Default by its name.
func ServiceByName(name string) (Service, bool) { return Default.ServiceByName(name) }
