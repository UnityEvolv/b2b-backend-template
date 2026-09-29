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
