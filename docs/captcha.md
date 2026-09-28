# CAPTCHA on public forms

Bot protection for the forms anyone can reach without signing in: self-serve
signup first, then forgot password and invite acceptance. Set up once in
[pkg/captcha](../pkg/captcha/captcha.go); a form uses it, never reimplements it.

```go
verifier, err := captcha.FromEnv(env, logger)   // recaptcha, or off on a laptop
mux.Handle("POST /v1/signups", captcha.Require(verifier, "signup", logger, signupHandler))
```

The browser gets a token from the widget for a named action and sends it in
`X-Captcha-Token`. `Require` verifies it with the provider before the handler
runs, because a token checked only in the browser proves nothing:

| what happened | response |
| --- | --- |
| no token | 400 `captcha.required` |
| provider refused it, wrong action, or score below the threshold | 403 `captcha.failed` |
| provider unreachable | 503 `unavailable`, never a silent pass |

Each refusal is logged with the action and the reason, so a page sending
the wrong action name is found on its first request.

## Provider

reCAPTCHA v3, scored: no puzzle, a score from 0 to 1 per request, with a
threshold (`CAPTCHA_MIN_SCORE_PERCENT`, default 50). The `Verifier` interface
is small on purpose: Cloudflare Turnstile is worth adding for customers who
object to sending anything to Google, and it slots in beside `Recaptcha`.

The widget's origins are declared once, by the verifier, as `csp.Origins`
(script, frame and connect), and the frontend's header definition carries the
same list. Nothing else in the policy names them.

## Configuration

| name | meaning |
| --- | --- |
| `CAPTCHA_PROVIDER` | `recaptcha` (default) or `off` |
| `RECAPTCHA_SECRET` | the secret key, from the secret manager; the site key is public and lives in the web build (`VITE_RECAPTCHA_SITE_KEY`) |
| `CAPTCHA_MIN_SCORE_PERCENT` | the lowest score accepted, default 50 |

`off` is refused unless `ENVIRONMENT=local`: a laptop can test a form without
a provider account, and a deployed service cannot be configured to skip the
check. With the provider off, the frontend component sends no token and the
middleware asks for none.

This covers public forms only. Rate limiting on authenticated endpoints is
[pkg/ratelimit](../pkg/ratelimit) and is not solved by a CAPTCHA.
