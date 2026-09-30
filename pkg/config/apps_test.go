package config_test

import (
	"reflect"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
)

func TestAppsDeriveFromTheBase(t *testing.T) {
	t.Setenv("APP_NAMES", "")
	t.Setenv("PLATFORM_APP", "")
	env := &config.Env{}
	apps := config.AppsFrom(env, "Example.com")
	if err := env.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"account":  "https://example.com",
		"admin":    "https://admin.example.com",
		"platform": "https://platform.example.com",
	}
	if apps.Main() != "account" || apps.Platform != "platform" || !reflect.DeepEqual(apps.Origins, want) {
		t.Fatalf("got %v %v %s", apps.Names, apps.Origins, apps.Platform)
	}
}

func TestThePlatformAppIsConfigured(t *testing.T) {
	// A product with no platform app of its own: operators use the main one.
	t.Setenv("APP_NAMES", "portal, console")
	if apps := config.AppsFrom(&config.Env{}, "example.com"); apps.Platform != "portal" {
		t.Errorf("no platform app: %q", apps.Platform)
	}
	t.Setenv("PLATFORM_APP", "Console")
	if apps := config.AppsFrom(&config.Env{}, "example.com"); apps.Platform != "console" {
		t.Errorf("named: %q", apps.Platform)
	}
	t.Setenv("PLATFORM_APP", "ops")
	env := &config.Env{}
	config.AppsFrom(env, "example.com")
	if env.Err() == nil {
		t.Error("PLATFORM_APP outside APP_NAMES accepted")
	}
}

func TestAppsAreConfigured(t *testing.T) {
	t.Setenv("APP_NAMES", "Portal, console")
	t.Setenv("APP_ORIGIN_CONSOLE", "http://localhost:5174/")
	env := &config.Env{}
	apps := config.AppsFrom(env, "")
	if apps.Main() != "portal" || apps.Origins["console"] != "http://localhost:5174" {
		t.Fatalf("got %v %v", apps.Names, apps.Origins)
	}
	// Without a base hostname every origin must be named.
	if err := env.Err(); err == nil {
		t.Fatal("APP_ORIGIN_PORTAL missing, and no error")
	}
}
