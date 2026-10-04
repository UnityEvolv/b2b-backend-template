package onboarding_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/onboarding"
)

func TestTheCoreStepsComeFirstAndAProductsFollow(t *testing.T) {
	r := onboarding.New()
	var ids []string
	for _, s := range r.Steps() {
		ids = append(ids, s.ID)
		if s.App != onboarding.DefaultApp {
			t.Errorf("%s: app %q", s.ID, s.App)
		}
	}
	if strings.Join(ids, ",") != "verify_domain,invite_teammates,set_up_sso,choose_plan" {
		t.Fatalf("core steps: %v", ids)
	}
	if err := r.Load(`[{"id":"create_project","label":"Create your first project","href":"/projects","app":"account","service":"projects"}]`); err != nil {
		t.Fatal(err)
	}
	steps := r.Steps()
	if last := steps[len(steps)-1]; last.ID != "create_project" || last.App != "account" || last.URLVar() != "PROJECTS_URL" {
		t.Fatalf("product step: %+v", last)
	}
	// Registering an id again replaces it in place.
	r.Register(onboarding.Step{ID: onboarding.SetUpSSO, Label: "Connect your directory", Href: "/sso", Service: "identity"})
	if s, _ := r.Step(onboarding.SetUpSSO); s.Label != "Connect your directory" || r.Steps()[2].ID != onboarding.SetUpSSO {
		t.Fatalf("replaced: %+v", r.Steps())
	}
}

func TestAMalformedStepIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":       `{`,
		"unknown field":  `[{"id":"x","label":"X","href":"/x","service":"p","done":true}]`,
		"bad id":         `[{"id":"Create Project","label":"X","href":"/x","service":"p"}]`,
		"no label":       `[{"id":"x","label":" ","href":"/x","service":"p"}]`,
		"absolute href":  `[{"id":"x","label":"X","href":"https://evil.example/x","service":"p"}]`,
		"protocol href":  `[{"id":"x","label":"X","href":"//evil.example/x","service":"p"}]`,
		"no service":     `[{"id":"x","label":"X","href":"/x"}]`,
		"bad app":        `[{"id":"x","label":"X","href":"/x","app":"Admin App","service":"p"}]`,
		"bad service":    `[{"id":"x","label":"X","href":"/x","service":"P_S"}]`,
		"label too long": `[{"id":"x","label":"` + strings.Repeat("x", 101) + `","href":"/x","service":"p"}]`,
	} {
		if _, err := onboarding.Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("Register accepted a step with no service")
		}
	}()
	onboarding.New().Register(onboarding.Step{ID: "x", Label: "X", Href: "/x"})
}

func TestLocateNamesWhatIsMissing(t *testing.T) {
	r := onboarding.New()
	r.Register(onboarding.Step{ID: "create_project", Label: "Create a project", Href: "/projects", Service: "projects"})
	err := r.Locate(func(string) string { return "" }, "organization")
	if err == nil || !strings.Contains(err.Error(), "IDENTITY_URL") || !strings.Contains(err.Error(), "PROJECTS_URL") {
		t.Fatalf("missing: %v", err)
	}
	env := map[string]string{"IDENTITY_URL": "http://identity", "PROJECTS_URL": "http://projects"}
	if err := r.Locate(func(k string) string { return env[k] }, "organization"); err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Steps() {
		if (s.Service == "organization") != (s.URL == "") {
			t.Errorf("%s: url %q", s.ID, s.URL)
		}
	}
}

func TestTheClientAsksAsThisServiceAndGivesUpInTime(t *testing.T) {
	org := uuid.New()
	var seen *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		switch {
		case strings.HasSuffix(r.URL.Path, "/slow"):
			time.Sleep(onboarding.Timeout + 500*time.Millisecond)
		case strings.HasSuffix(r.URL.Path, "/broken"):
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(onboarding.Status{Done: true})
	}))
	defer srv.Close()
	c := onboarding.NewClient(auth.StaticToken("svc"), nil)
	step := onboarding.Step{ID: "create_project", Service: "projects", URL: srv.URL}

	done, err := c.Done(context.Background(), step, org)
	if err != nil || !done {
		t.Fatalf("done: %v %v", done, err)
	}
	if seen.URL.Path != "/v1/internal/organizations/"+org.String()+"/onboarding/create_project" || seen.Header.Get("Authorization") != "Bearer svc" {
		t.Fatalf("asked %s with %q", seen.URL.Path, seen.Header.Get("Authorization"))
	}
	step.ID = "broken"
	if _, err := c.Done(context.Background(), step, org); err == nil {
		t.Error("a 500 taken as an answer")
	}
	step.ID = "slow"
	start := time.Now()
	if _, err := c.Done(context.Background(), step, org); err == nil {
		t.Error("a late answer taken")
	}
	if took := time.Since(start); took > onboarding.Timeout+400*time.Millisecond {
		t.Errorf("waited %v", took)
	}
}
