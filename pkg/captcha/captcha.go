// Package captcha is bot protection for public forms: self-serve
// signup, forgot password, invite acceptance. The browser gets a token from
// the provider's widget and sends it with the request; the server verifies
// it with the provider, because a token checked only in the browser proves
// nothing.
//
// The provider is reCAPTCHA v3. The interface is small so Turnstile can be a
// second implementation for customers who object to Google.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/csp"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Header carries the token from a public form. The frontend component sets
// it; the middleware reads it.
const Header = "X-Captcha-Token"

// Errors a verification can end in. The response says which so a person can
// retry a stale token, and the log says which so a wrong action name in a
// page is found on the first request rather than by the abuse it lets in.
var (
	ErrMissing     = errors.New("captcha: no token")
	ErrInvalid     = errors.New("captcha: token refused by the provider")
	ErrLowScore    = errors.New("captcha: score below the threshold")
	ErrWrongAction = errors.New("captcha: token was issued for another action")
	ErrUnavailable = errors.New("captcha: provider unreachable")
)

// Verifier checks a token.
type Verifier interface {
	// Verify is nil when token was issued for action, recently, to a client
	// the provider believes is a person. remoteIP may be empty.
	Verify(ctx context.Context, token, action, remoteIP string) error
}

// Recaptcha verifies with reCAPTCHA v3.
type Recaptcha struct {
	Secret string
	// MinScore is the lowest score accepted, 0 to 1. reCAPTCHA's own
	// guidance starts at 0.5.
	MinScore float64
	// Endpoint overrides the verification URL, for tests.
	Endpoint string
	HTTP     *http.Client
}

// The provider's verification endpoint and the origins its widget needs the
// browser to reach. One place, so a provider swap touches nothing else.
const (
	recaptchaVerify = "https://www.google.com/recaptcha/api/siteverify"
)

var recaptchaOrigins = csp.Origins{
	Script:  []string{"https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"},
	Frame:   []string{"https://www.google.com/recaptcha/"},
	Connect: []string{"https://www.google.com/recaptcha/"},
}

// CSPOrigins is what the reCAPTCHA widget needs the policy to allow.
func (r Recaptcha) CSPOrigins() csp.Origins { return recaptchaOrigins }

// Verify checks token with reCAPTCHA.
func (r Recaptcha) Verify(ctx context.Context, token, action, remoteIP string) error {
	if strings.TrimSpace(token) == "" {
		return ErrMissing
	}
	endpoint := r.Endpoint
	if endpoint == "" {
		endpoint = recaptchaVerify
	}
	form := url.Values{"secret": {r.Secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	var body struct {
		Success    bool     `json:"success"`
		Score      float64  `json:"score"`
		Action     string   `json:"action"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !body.Success {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(body.ErrorCodes, ","))
	}
	if body.Action != action {
		return fmt.Errorf("%w: %q", ErrWrongAction, body.Action)
	}
	min := r.MinScore
	if min <= 0 {
		min = 0.5
	}
	if body.Score < min {
		return fmt.Errorf("%w: %.2f", ErrLowScore, body.Score)
	}
	return nil
}

// Disabled accepts every request. Local development only: it lets a form be
// tested without a provider account, and a deployed service refuses to
// start with it.
type Disabled struct{}

// Verify is always nil.
func (Disabled) Verify(context.Context, string, string, string) error { return nil }

// CSPOrigins is nothing: no widget is loaded.
func (Disabled) CSPOrigins() csp.Origins { return csp.Origins{} }

// FromEnv is the verifier configuration names: CAPTCHA_PROVIDER is
// "recaptcha" (RECAPTCHA_SECRET required, CAPTCHA_MIN_SCORE optional) or
// "off". "off" is refused unless ENVIRONMENT is "local".
func FromEnv(env *config.Env, logger *slog.Logger) (Verifier, error) {
	provider := env.String("CAPTCHA_PROVIDER", "recaptcha")
	switch provider {
	case "recaptcha":
		secret := env.Required("RECAPTCHA_SECRET")
		if err := env.Err(); err != nil {
			return nil, err
		}
		return Recaptcha{Secret: secret, MinScore: float64(env.Int("CAPTCHA_MIN_SCORE_PERCENT", 50)) / 100}, nil
	case "off":
		if env.String("ENVIRONMENT", "") != "local" {
			return nil, errors.New("captcha: CAPTCHA_PROVIDER=off is for local development only")
		}
		logger.Warn("captcha is off: every public form accepts every request", "alert", false)
		return Disabled{}, nil
	}
	return nil, fmt.Errorf("captcha: CAPTCHA_PROVIDER %q is not recaptcha or off", provider)
}

// Error envelope codes.
const (
	CodeRequired = "captcha.required"
	CodeFailed   = "captcha.failed"
)

// Require wraps a public form's handler: the request must carry a token in
// Header that verifies for action. A missing token is 400; a refused one is
// 403; a provider that cannot be reached is 503, never a silent pass.
func Require(v Verifier, action string, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(Header)
		if _, disabled := v.(Disabled); !disabled && token == "" {
			httpx.WriteError(w, http.StatusBadRequest, CodeRequired, "This form needs a CAPTCHA token.")
			return
		}
		err := v.Verify(r.Context(), token, action, httpx.RequestInfoFrom(r.Context()).ClientIP)
		switch {
		case err == nil:
			next.ServeHTTP(w, r)
		case errors.Is(err, ErrUnavailable):
			logger.Error("captcha provider unreachable", "action", action, "error", err)
			httpx.WriteError(w, http.StatusServiceUnavailable, httpx.CodeUnavailable, "The CAPTCHA service is not reachable. Try again in a moment.")
		default:
			logger.Warn("captcha refused", "action", action, "error", err)
			httpx.WriteError(w, http.StatusForbidden, CodeFailed, "The CAPTCHA check did not pass. Reload the page and try again.")
		}
	})
}
