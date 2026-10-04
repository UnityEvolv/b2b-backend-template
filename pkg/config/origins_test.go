package config_test

import (
	"reflect"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
)

func TestEveryHostDerivesFromTheBase(t *testing.T) {
	h := config.HostsFor(" App.Example.com ")
	want := config.Hosts{
		Base:     "app.example.com",
		Account:  "app.example.com",
		Admin:    "admin.app.example.com",
		Platform: "platform.app.example.com",
		API:      "api.app.example.com",
	}
	if h != want {
		t.Fatalf("got %+v\nwant %+v", h, want)
	}
}

func TestAllowedOrigins(t *testing.T) {
	t.Setenv("APP_NAMES", "")
	t.Setenv("ALLOWED_ORIGINS", " b2bapp://app/ ,")
	got := config.AllowedOrigins(&config.Env{}, "example.com")
	want := []string{
		"https://example.com",
		"https://admin.example.com",
		"https://platform.example.com",
		"b2bapp://app",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// A laptop has no base hostname, only the dev servers it names.
	t.Setenv("ALLOWED_ORIGINS", "http://localhost:5173")
	local := config.AllowedOrigins(&config.Env{}, "")
	if !reflect.DeepEqual(local, []string{"http://localhost:5173"}) {
		t.Fatalf("local: %v", local)
	}
	// A product's own apps are allowed too.
	t.Setenv("APP_NAMES", "portal")
	t.Setenv("ALLOWED_ORIGINS", "")
	if got := config.AllowedOrigins(&config.Env{}, "example.com"); !reflect.DeepEqual(got, []string{"https://example.com"}) {
		t.Fatalf("own apps: %v", got)
	}
}

func TestBrand(t *testing.T) {
	t.Setenv("PRODUCT_NAME", "")
	t.Setenv("PRODUCT_ID", "")
	t.Setenv("REDIS_PREFIX", "")
	env := &config.Env{}
	b := config.BrandFrom(env)
	if b != config.DefaultBrand || config.RedisFrom(env, b).Notify() != "b2bapp:notify" {
		t.Fatalf("defaults: %+v", b)
	}
	t.Setenv("PRODUCT_NAME", "Acme Cloud")
	t.Setenv("PRODUCT_ID", "acme-cloud")
	b = config.BrandFrom(env)
	if b.Name != "Acme Cloud" || config.RedisFrom(env, b).Key("focus", "x") != "acme-cloud:focus:x" {
		t.Fatalf("configured: %+v", b)
	}
	t.Setenv("PRODUCT_ID", "Not An Id")
	config.BrandFrom(env)
	if env.Err() == nil {
		t.Fatal("a bad PRODUCT_ID was taken")
	}
}

// The identity service's cookies and the SCIM token prefix come from the
// product's id, or their own settings; none names a product of its own.
func TestCookiesAndTokenPrefixFollowTheBrand(t *testing.T) {
	t.Setenv("COOKIE_PREFIX", "")
	t.Setenv("SCIM_TOKEN_PREFIX", "")
	env := &config.Env{}
	if c := config.CookiesFrom(env, config.DefaultBrand); c != config.DefaultCookies || c.Session != "b2bapp_session" || c.SignIn != "b2bapp_signin" {
		t.Fatalf("default cookies: %+v", c)
	}
	if p := config.SCIMTokenPrefixFrom(env, config.DefaultBrand); p != config.DefaultSCIMTokenPrefix || p != "b2bapp_scim_" {
		t.Fatalf("default SCIM prefix: %q", p)
	}
	acme := config.Brand{Name: "Acme Cloud", ID: "acme-cloud"}
	if c := config.CookiesFrom(env, acme); c.Session != "acme_cloud_session" || c.SignIn != "acme_cloud_signin" {
		t.Errorf("cookies under the product id: %+v", c)
	}
	if p := config.SCIMTokenPrefixFrom(env, acme); p != "acme_cloud_scim_" {
		t.Errorf("SCIM prefix under the product id: %q", p)
	}
	t.Setenv("COOKIE_PREFIX", "ac")
	t.Setenv("SCIM_TOKEN_PREFIX", "acs_")
	if c := config.CookiesFrom(env, acme); c.Session != "ac_session" {
		t.Errorf("configured cookies: %+v", c)
	}
	if p := config.SCIMTokenPrefixFrom(env, acme); p != "acs_" {
		t.Errorf("configured SCIM prefix: %q", p)
	}
	if env.Err() != nil {
		t.Fatal(env.Err())
	}
	t.Setenv("COOKIE_PREFIX", "a b;c")
	config.CookiesFrom(env, acme)
	if env.Err() == nil {
		t.Fatal("a bad COOKIE_PREFIX was taken")
	}
}

// API keys and personal access tokens start with the product's id too, one
// prefix per kind, unless the settings name their own.
func TestKeyPrefixesFollowTheBrand(t *testing.T) {
	t.Setenv("API_KEY_PREFIX", "")
	t.Setenv("PAT_PREFIX", "")
	env := &config.Env{}
	if p := config.KeyPrefixesFrom(env, config.DefaultBrand); p != config.DefaultKeyPrefixes || p.Org != "b2bapp_ak_" || p.Personal != "b2bapp_pat_" {
		t.Fatalf("default: %+v", p)
	}
	if p := config.KeyPrefixesFrom(env, config.Brand{Name: "Acme Cloud", ID: "acme-cloud"}); p.Org != "acme_cloud_ak_" || p.Personal != "acme_cloud_pat_" {
		t.Errorf("under the product id: %+v", p)
	}
	t.Setenv("API_KEY_PREFIX", "acme_key_")
	t.Setenv("PAT_PREFIX", "acme_tok_")
	if p := config.KeyPrefixesFrom(env, config.DefaultBrand); p.Org != "acme_key_" || p.Personal != "acme_tok_" || env.Err() != nil {
		t.Errorf("configured: %+v %v", p, env.Err())
	}
	t.Setenv("PAT_PREFIX", "acme_key_")
	config.KeyPrefixesFrom(env, config.DefaultBrand)
	if env.Err() == nil {
		t.Fatal("the same prefix for both kinds was taken")
	}
}
