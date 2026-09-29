package config

import "strings"

// DefaultApps are the web apps a product has unless APP_NAMES says otherwise:
// the one its people use, the org admin console, and the platform console.
// The first is the main app.
var DefaultApps = []string{"account", "admin", "platform"}

// Apps is every web app a sign-in, an invite or an emailed link may open.
type Apps struct {
	// Names in the configured order; Names[0] is the main app, where a link
	// goes when nothing names another.
	Names []string
	// Origins is each app's origin, by name.
	Origins map[string]string
}

// Main is the main app's name.
func (a Apps) Main() string {
	if len(a.Names) == 0 {
		return ""
	}
	return a.Names[0]
}

// AppsFrom reads the web apps: APP_NAMES lists them (DefaultApps when unset),
// and APP_ORIGIN_<NAME> gives each one's origin. With a base hostname the
// origin defaults to https://<base> for the main app and
// https://<name>.<base> for every other; without one, each must be set.
func AppsFrom(e *Env, base string) Apps {
	names := appNames(e)
	apps := Apps{Names: names, Origins: make(map[string]string, len(names))}
	for i, name := range names {
		key := appOriginKey(name)
		origin := e.String(key, derivedOrigin(base, name, i == 0))
		if origin == "" {
			e.Required(key)
		}
		apps.Origins[name] = strings.TrimSuffix(origin, "/")
	}
	return apps
}

// appNames is APP_NAMES, lower-cased, or DefaultApps.
func appNames(e *Env) []string {
	names := e.List("APP_NAMES")
	if len(names) == 0 {
		return append([]string(nil), DefaultApps...)
	}
	for i, n := range names {
		names[i] = strings.ToLower(n)
	}
	return names
}

// appOriginKey is the setting that names an app's origin.
func appOriginKey(name string) string {
	return "APP_ORIGIN_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// derivedOrigin is where an app lives under base: the main app at the base
// itself, every other at <name>.<base>. Empty without a base.
func derivedOrigin(base, name string, main bool) string {
	base = strings.TrimSpace(strings.ToLower(base))
	if base == "" {
		return ""
	}
	if main {
		return "https://" + base
	}
	return "https://" + name + "." + base
}
