package config_test

import (
	"reflect"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
)

func TestAppsDeriveFromTheBase(t *testing.T) {
	t.Setenv("APP_NAMES", "")
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
	if apps.Main() != "account" || !reflect.DeepEqual(apps.Origins, want) {
		t.Fatalf("got %v %v", apps.Names, apps.Origins)
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
