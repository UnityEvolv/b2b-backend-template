// Package db is the database plumbing every service shares.
package db

// Service is one service that owns one Postgres schema.
//
// One schema per service, one login role per service, and the role can reach
// its own schema and nothing else. A service that needs another's data calls
// its API; the database refuses the shortcut.
type Service struct {
	// Name is the service's directory under services/.
	Name string
	// Schema is the Postgres schema it owns. Usually the same as Name; `users`
	// rather than `user`, because `user` is a reserved word in Postgres.
	Schema string
}

// Role is the login role the service connects as. It owns the schema, so the
// service runs its own migrations, and it has no privileges anywhere else.
func (s Service) Role() string { return "svc_" + s.Schema }

// Services is every service that owns a schema. Adding a service here is what
// gives it a schema and a role, locally and in every environment.
var Services = []Service{
	{Name: "organization", Schema: "organization"},
	{Name: "identity", Schema: "identity"},
	{Name: "user", Schema: "users"},
	// authorization is reserved too.
	{Name: "authorization", Schema: "authz"},
	{Name: "audit", Schema: "audit"},
	{Name: "notification", Schema: "notification"},
	{Name: "billing", Schema: "billing"},
}

// ServiceByName finds a service by its directory name.
func ServiceByName(name string) (Service, bool) {
	for _, s := range Services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}
