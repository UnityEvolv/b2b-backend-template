package config

import "strings"

// Hostnames derived from the one base hostname (UO-42): everything the product
// is reached at is a subdomain of it, so a move to another domain is a change
// to one variable.
const (
	SubdomainAdmin    = "admin"
	SubdomainPlatform = "platform"
	SubdomainAPI      = "api"
	SubdomainRealtime = "rt"
	SubdomainTURN     = "turn"
)

// Hosts is where each piece of the product lives, derived from base.
type Hosts struct {
	Base     string
	Ofis     string
	Admin    string
	Platform string
	API      string
	Realtime string
	TURN     string
}

// HostsFor derives every hostname from base, such as "unityofis.unityevolv.com".
func HostsFor(base string) Hosts {
	base = strings.TrimSpace(strings.ToLower(base))
	sub := func(name string) string { return name + "." + base }
	return Hosts{
		Base:     base,
		Ofis:     base,
		Admin:    sub(SubdomainAdmin),
		Platform: sub(SubdomainPlatform),
		API:      sub(SubdomainAPI),
		Realtime: sub(SubdomainRealtime),
		TURN:     sub(SubdomainTURN),
	}
}

// AppOrigins is every origin a browser may call the API from: the three web
// apps under base, plus extra, which is how the local stack names the Vite dev
// servers and how the desktop shell's scheme is added. Empty base means no
// derived origins, which is what a laptop wants.
func AppOrigins(base string, extra []string) []string {
	var origins []string
	if base != "" {
		h := HostsFor(base)
		origins = append(origins, "https://"+h.Ofis, "https://"+h.Admin, "https://"+h.Platform)
	}
	for _, o := range extra {
		if o = strings.TrimSuffix(strings.TrimSpace(o), "/"); o != "" {
			origins = append(origins, o)
		}
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
