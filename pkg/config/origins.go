package config

import "strings"

// Hostnames derived from the one base hostname: everything the product is
// reached at is the base or a subdomain of it, so a move to another domain
// is a change to one variable.
const (
	SubdomainAdmin    = "admin"
	SubdomainPlatform = "platform"
	SubdomainAPI      = "api"
)

// Hosts is where each piece of the product lives, derived from base: the
// default web apps (see DefaultApps) and the API.
type Hosts struct {
	Base     string
	Account  string
	Admin    string
	Platform string
	API      string
}

// HostsFor derives every hostname from base, such as "example.com".
func HostsFor(base string) Hosts {
	base = strings.TrimSpace(strings.ToLower(base))
	sub := func(name string) string { return name + "." + base }
	return Hosts{
		Base:     base,
		Account:  base,
		Admin:    sub(SubdomainAdmin),
		Platform: sub(SubdomainPlatform),
		API:      sub(SubdomainAPI),
	}
}

// AllowedOrigins is every origin a browser may call the API from: each web
// app APP_NAMES lists (at APP_ORIGIN_<NAME>, or derived from base as
// AppsFrom does), plus ALLOWED_ORIGINS, which is how the local stack names
// the Vite dev servers and how the desktop shell's scheme is added. Empty
// base means no derived origins, which is what a laptop wants. Unlike
// AppsFrom, an app with no origin is left out rather than required.
func AllowedOrigins(e *Env, base string) []string {
	var origins []string
	seen := map[string]bool{}
	add := func(o string) {
		if o = strings.TrimSuffix(strings.TrimSpace(o), "/"); o != "" && !seen[o] {
			seen[o] = true
			origins = append(origins, o)
		}
	}
	for i, name := range appNames(e) {
		add(e.String(appOriginKey(name), derivedOrigin(base, name, i == 0)))
	}
	for _, o := range e.List("ALLOWED_ORIGINS") {
		add(o)
	}
	return origins
}

// List splits a comma-separated setting into its trimmed, non-empty parts.
func (e *Env) List(name string) []string {
	var out []string
	for _, part := range strings.Split(e.String(name, ""), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
