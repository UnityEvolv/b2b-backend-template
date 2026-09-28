package captcha_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/captcha"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// fakeRecaptcha answers siteverify the way Google does, keyed by the token.
func fakeRecaptcha(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("secret") != secret {
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error-codes": []string{"invalid-input-secret"}})
			return
		}
		switch r.Form.Get("response") {
		case "human-signup":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "score": 0.9, "action": "signup"})
		case "bot-signup":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "score": 0.1, "action": "signup"})
		case "human-login":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "score": 0.9, "action": "login"})
		case "broken":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
		}
	}))
}

func TestRecaptchaVerify(t *testing.T) {
	srv := fakeRecaptcha(t, "s3cret")
	defer srv.Close()
	v := captcha.Recaptcha{Secret: "s3cret", Endpoint: srv.URL}
	ctx := t.Context()

	if err := v.Verify(ctx, "human-signup", "signup", "203.0.113.9"); err != nil {
		t.Errorf("a person: %v", err)
	}
	cases := map[string]error{
		"":            captcha.ErrMissing,
		"stale":       captcha.ErrInvalid,
		"bot-signup":  captcha.ErrLowScore,
		"human-login": captcha.ErrWrongAction,
		"broken":      captcha.ErrUnavailable,
	}
	for token, want := range cases {
		if err := v.Verify(ctx, token, "signup", ""); !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", token, err, want)
		}
	}
	// A wrong secret is the provider refusing, not a pass.
	if err := (captcha.Recaptcha{Secret: "wrong", Endpoint: srv.URL}).Verify(ctx, "human-signup", "signup", ""); !errors.Is(err, captcha.ErrInvalid) {
		t.Errorf("wrong secret: %v", err)
	}
	// The threshold is configurable.
	if err := (captcha.Recaptcha{Secret: "s3cret", Endpoint: srv.URL, MinScore: 0.95}).Verify(ctx, "human-signup", "signup", ""); !errors.Is(err, captcha.ErrLowScore) {
		t.Errorf("0.9 under a 0.95 threshold: %v", err)
	}
}

// A public form behind Require refuses a missing or bad token and passes a
// good one, in the error envelope; the provider being down is 503, never a
// pass.
func TestRequireOnAPublicForm(t *testing.T) {
	srv := fakeRecaptcha(t, "s3cret")
	defer srv.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	form := captcha.Require(captcha.Recaptcha{Secret: "s3cret", Endpoint: srv.URL}, "signup", logger,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }))

	post := func(token string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/signup", nil)
		if token != "" {
			req.Header.Set(captcha.Header, token)
		}
		rec := httptest.NewRecorder()
		form.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	if status, _ := post("human-signup"); status != http.StatusCreated {
		t.Errorf("a person: %d", status)
	}
	if status, body := post(""); status != http.StatusBadRequest || body["code"] != captcha.CodeRequired {
		t.Errorf("no token: %d %v", status, body)
	}
	for _, token := range []string{"stale", "bot-signup", "human-login"} {
		if status, body := post(token); status != http.StatusForbidden || body["code"] != captcha.CodeFailed {
			t.Errorf("%s: %d %v", token, status, body)
		}
	}
	if status, body := post("broken"); status != http.StatusServiceUnavailable || body["code"] != httpx.CodeUnavailable {
		t.Errorf("provider down: %d %v", status, body)
	}

	// Disabled, for local development: no token needed.
	off := captcha.Require(captcha.Disabled{}, "signup", logger,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }))
	rec := httptest.NewRecorder()
	off.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/signup", nil))
	if rec.Code != http.StatusCreated {
		t.Errorf("disabled: %d", rec.Code)
	}
}

func TestFromEnvRefusesOffOutsideLocal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// config.Env reads the process environment; each case sets exactly its own.
	env := func(vars map[string]string) *config.Env {
		for _, name := range []string{"CAPTCHA_PROVIDER", "ENVIRONMENT", "RECAPTCHA_SECRET", "CAPTCHA_MIN_SCORE_PERCENT"} {
			t.Setenv(name, vars[name])
		}
		return &config.Env{}
	}
	if _, err := captcha.FromEnv(env(map[string]string{"CAPTCHA_PROVIDER": "off", "ENVIRONMENT": "production"}), logger); err == nil {
		t.Error("off accepted in production")
	}
	if v, err := captcha.FromEnv(env(map[string]string{"CAPTCHA_PROVIDER": "off", "ENVIRONMENT": "local"}), logger); err != nil || v != (captcha.Disabled{}) {
		t.Errorf("off in local: %v %v", v, err)
	}
	if _, err := captcha.FromEnv(env(map[string]string{}), logger); err == nil {
		t.Error("recaptcha without a secret accepted")
	}
	v, err := captcha.FromEnv(env(map[string]string{"RECAPTCHA_SECRET": "x", "CAPTCHA_MIN_SCORE_PERCENT": "70"}), logger)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := v.(captcha.Recaptcha); !ok || r.MinScore != 0.7 {
		t.Errorf("recaptcha from env: %+v", v)
	}
	// The widget's origins are declared once, for the policy.
	if o := v.(captcha.Recaptcha).CSPOrigins(); len(o.Script) == 0 || len(o.Frame) == 0 {
		t.Errorf("no origins declared: %+v", o)
	}
}
