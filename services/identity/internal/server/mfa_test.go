package server_test

import (
	"encoding/base32"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/totp"
)

// app is the authenticator app: it holds the secret and makes codes. offset
// picks a step near now, since a code is never accepted twice and a test
// runs within one step.
type app struct{ secret []byte }

func appFor(t *testing.T, enrolment map[string]any) app {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolment["secret"].(string))
	if err != nil || len(secret) != totp.SecretLen {
		t.Fatalf("secret: %v %v", enrolment["secret"], err)
	}
	return app{secret: secret}
}

func (a app) code(offset int64) string { return totp.Code(a.secret, totp.Step(time.Now())+offset) }

// signInLocal posts the credentials and returns the status and body.
func signInLocal(t *testing.T, b *browser, email, pw string) (int, map[string]any) {
	t.Helper()
	rec := b.do(http.MethodPost, "/v1/sign-in/local", "", map[string]any{"email": email, "password": pw})
	return rec.Code, body(t, rec)
}

func (f *fixture) admin(t *testing.T, org uuid.UUID) string {
	t.Helper()
	id := uuid.NewString()
	f.grants[org.String()+"/"+id] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	raw, err := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org.String(), MembershipID: id}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A local user enrols, is challenged at sign-in,
// recovers with a code, and an admin can reset their MFA.
func TestMfaEnrolChallengeRecoverAndReset(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	ada := f.account(t, "ada@example.com", acme, "adas-long-password")
	code, tok := signInLocal(t, b, "ada@example.com", "adas-long-password")
	if code != http.StatusOK {
		t.Fatalf("sign-in without MFA: %d %v", code, tok)
	}
	token := tok["access_token"].(string)

	// Nothing yet. Enrol: a secret for the app, confirmed with a code.
	if out := body(t, b.do(http.MethodGet, "/v1/mfa", token, nil)); out["enrolled"] != false || out["required"] != false {
		t.Errorf("before: %v", out)
	}
	rec := b.do(http.MethodPost, "/v1/mfa/totp", token, nil)
	enrolment := body(t, rec)
	if rec.Code != http.StatusOK || enrolment["otpauth_uri"] == nil {
		t.Fatalf("enrol: %d %v", rec.Code, enrolment)
	}
	authn := appFor(t, enrolment)
	if rec := b.do(http.MethodPost, "/v1/mfa/totp/confirm", token, map[string]any{"code": "000000"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong first code: %d", rec.Code)
	}
	// Not in force until confirmed: a sign-in still needs no code.
	if code, _ := signInLocal(t, f.browser(), "ada@example.com", "adas-long-password"); code != http.StatusOK {
		t.Errorf("sign-in before confirming: %d", code)
	}
	rec = b.do(http.MethodPost, "/v1/mfa/totp/confirm", token, map[string]any{"code": authn.code(0)})
	codes, _ := body(t, rec)["recovery_codes"].([]any)
	if rec.Code != http.StatusOK || len(codes) != totp.RecoveryCodes {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	if f.audited("mfa.enrolled") != 1 {
		t.Errorf("enrolment audited %d times", f.audited("mfa.enrolled"))
	}
	if rec := b.do(http.MethodPost, "/v1/mfa/totp", token, nil); rec.Code != http.StatusConflict {
		t.Errorf("enrolling again: %d", rec.Code)
	}
	if out := body(t, b.do(http.MethodGet, "/v1/mfa", token, nil)); out["enrolled"] != true || out["recovery_codes_left"] != float64(10) {
		t.Errorf("after: %v", out)
	}

	// Challenged at sign-in: the password alone parks the sign-in; a wrong
	// code and a replayed code are refused; a fresh code, then a recovery
	// code, get in.
	phone := f.browser()
	code, out := signInLocal(t, phone, "ada@example.com", "adas-long-password")
	challenge, _ := out["challenge_token"].(string)
	if code != http.StatusAccepted || out["mfa"] != "challenge" || challenge == "" {
		t.Fatalf("challenged: %d %v", code, out)
	}
	if _, ok := phone.cookies[sessionName]; ok {
		t.Error("a session before the code")
	}
	mfa := func(b *browser, challenge, code string) (int, map[string]any) {
		rec := b.do(http.MethodPost, "/v1/sign-in/mfa", "", map[string]any{"challenge_token": challenge, "code": code})
		return rec.Code, body(t, rec)
	}
	if code, out := mfa(phone, challenge, "123456"); code != http.StatusUnauthorized || out["code"] != "mfa.code_invalid" {
		t.Errorf("wrong code: %d %v", code, out)
	}
	if code, out := mfa(phone, challenge, authn.code(0)); code != http.StatusUnauthorized || out["code"] != "mfa.code_invalid" {
		t.Errorf("the code used to confirm, again: %d %v", code, out)
	}
	code, tok = mfa(phone, challenge, authn.code(1))
	if code != http.StatusOK || tok["org_id"] != acme.String() {
		t.Fatalf("right code: %d %v", code, tok)
	}
	if _, ok := phone.cookies[sessionName]; !ok {
		t.Error("no session after the code")
	}
	if code, _ := mfa(phone, challenge, authn.code(1)); code != http.StatusUnauthorized {
		t.Errorf("challenge reused: %d", code)
	}
	tablet := f.browser()
	_, out = signInLocal(t, tablet, "ada@example.com", "adas-long-password")
	if code, _ := mfa(tablet, out["challenge_token"].(string), authn.code(1)); code != http.StatusUnauthorized {
		t.Errorf("a code accepted twice: %d", code)
	}
	if code, _ := mfa(tablet, out["challenge_token"].(string), codes[0].(string)); code != http.StatusOK {
		t.Errorf("recovery code: %d", code)
	}
	tv := f.browser()
	_, out = signInLocal(t, tv, "ada@example.com", "adas-long-password")
	if code, _ := mfa(tv, out["challenge_token"].(string), codes[0].(string)); code != http.StatusUnauthorized {
		t.Errorf("recovery code reused: %d", code)
	}
	if out := body(t, b.do(http.MethodGet, "/v1/mfa", token, nil)); out["recovery_codes_left"] != float64(9) {
		t.Errorf("codes left: %v", out)
	}
	// A fresh set replaces the old.
	rec = b.do(http.MethodPost, "/v1/mfa/recovery-codes", token, map[string]any{"code": codes[1]})
	fresh, _ := body(t, rec)["recovery_codes"].([]any)
	if rec.Code != http.StatusOK || len(fresh) != totp.RecoveryCodes {
		t.Fatalf("regenerate: %d %s", rec.Code, rec.Body.String())
	}
	tv2 := f.browser()
	_, out = signInLocal(t, tv2, "ada@example.com", "adas-long-password")
	if code, _ := mfa(tv2, out["challenge_token"].(string), codes[2].(string)); code != http.StatusUnauthorized {
		t.Errorf("an old recovery code after regenerating: %d", code)
	}

	// Turning it off: a wrong code no; while acme requires it no; then yes.
	admin := f.admin(t, acme)
	policy := "/v1/organizations/" + acme.String() + "/session-policy"
	if rec := b.do(http.MethodDelete, "/v1/mfa", token, map[string]any{"code": "000000"}); rec.Code != http.StatusForbidden {
		t.Errorf("disable with a wrong code: %d", rec.Code)
	}
	b.do(http.MethodPut, policy, admin, map[string]any{"lifetime_seconds": 30 * 24 * 3600, "idle_timeout_seconds": 24 * 3600, "mfa_required": true})
	if rec := b.do(http.MethodDelete, "/v1/mfa", token, map[string]any{"code": fresh[0]}); rec.Code != http.StatusForbidden || body(t, rec)["code"] != "mfa.required_by_organization" {
		t.Errorf("disable while required: %d %s", rec.Code, rec.Body.String())
	}
	b.do(http.MethodPut, policy, admin, map[string]any{"lifetime_seconds": 30 * 24 * 3600, "idle_timeout_seconds": 24 * 3600, "mfa_required": false})
	if rec := b.do(http.MethodDelete, "/v1/mfa", token, map[string]any{"code": fresh[1]}); rec.Code != http.StatusNoContent {
		t.Errorf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if out := body(t, b.do(http.MethodGet, "/v1/mfa", token, nil)); out["enrolled"] != false {
		t.Errorf("after disabling: %v", out)
	}
	if code, _ := signInLocal(t, f.browser(), "ada@example.com", "adas-long-password"); code != http.StatusOK {
		t.Errorf("sign-in after disabling: %d", code)
	}
	_ = ada
}

// The org setting: required means enrol before the first sign-in; and an
// admin resets a member who lost their device.
func TestMfaRequiredByTheOrganizationAndAdminReset(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	admin := f.admin(t, acme)
	policy := "/v1/organizations/" + acme.String() + "/session-policy"
	rec := b.do(http.MethodPut, policy, admin, map[string]any{"lifetime_seconds": 30 * 24 * 3600, "idle_timeout_seconds": 24 * 3600, "mfa_required": true})
	if rec.Code != http.StatusOK || body(t, rec)["mfa_required"] != true {
		t.Fatalf("require MFA: %d %s", rec.Code, rec.Body.String())
	}
	// Bob has no authenticator: the password is right, but he must set one
	// up before he gets a session.
	bob := f.account(t, "bob@example.com", acme, "bobs-long-password")
	code, out := signInLocal(t, b, "bob@example.com", "bobs-long-password")
	enrol, _ := out["enrollment_token"].(string)
	if code != http.StatusAccepted || out["mfa"] != "enroll" || enrol == "" {
		t.Fatalf("required and not enrolled: %d %v", code, out)
	}
	rec = b.do(http.MethodPost, "/v1/sign-in/mfa/enroll", "", map[string]any{"enrollment_token": enrol})
	if rec.Code != http.StatusOK {
		t.Fatalf("enrol at sign-in: %d %s", rec.Code, rec.Body.String())
	}
	authn := appFor(t, body(t, rec))
	if rec := b.do(http.MethodPost, "/v1/sign-in/mfa/confirm", "", map[string]any{"enrollment_token": enrol, "code": "000000"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong code at sign-in enrolment: %d", rec.Code)
	}
	rec = b.do(http.MethodPost, "/v1/sign-in/mfa/confirm", "", map[string]any{"enrollment_token": enrol, "code": authn.code(0)})
	if codes, _ := body(t, rec)["recovery_codes"].([]any); rec.Code != http.StatusOK || len(codes) != totp.RecoveryCodes {
		t.Fatalf("confirm at sign-in: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/sign-in/mfa/enroll", "", map[string]any{"enrollment_token": enrol}); rec.Code != http.StatusUnauthorized {
		t.Errorf("enrolment token reused: %d", rec.Code)
	}
	// Now a normal challenge.
	code, out = signInLocal(t, b, "bob@example.com", "bobs-long-password")
	if code != http.StatusAccepted || out["mfa"] != "challenge" {
		t.Fatalf("after enrolling: %d %v", code, out)
	}
	rec = b.do(http.MethodPost, "/v1/sign-in/mfa", "", map[string]any{"challenge_token": out["challenge_token"], "code": authn.code(1)})
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge after enrolling: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("refresh: %d", rec.Code)
	}

	// Bob loses his phone. A User cannot reset him; another org's admin
	// finds no member; acme's admin resets him, his session ends, and he
	// enrols again at his next sign-in.
	user, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: uuid.NewString()}, time.Hour)
	reset := "/v1/organizations/" + acme.String() + "/members/" + bob.String() + "/mfa"
	if rec := b.do(http.MethodDelete, reset, user, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a User resetting: %d", rec.Code)
	}
	if rec := b.do(http.MethodDelete, "/v1/organizations/"+globex.String()+"/members/"+bob.String()+"/mfa", f.admin(t, globex), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another org's admin: %d", rec.Code)
	}
	if rec := b.do(http.MethodDelete, reset, admin, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("session after a reset: %d", rec.Code)
	}
	if pushed := f.revocations("mfa_reset"); len(pushed) != 1 || pushed[0].Scope != "user" {
		t.Errorf("reset pushed: %+v", pushed)
	}
	if f.audited("mfa.reset") != 1 {
		t.Errorf("reset audited %d times", f.audited("mfa.reset"))
	}
	if code, out := signInLocal(t, f.browser(), "bob@example.com", "bobs-long-password"); code != http.StatusAccepted || out["mfa"] != "enroll" {
		t.Errorf("after a reset: %d %v", code, out)
	}
	if rec := b.do(http.MethodDelete, reset, admin, nil); rec.Code != http.StatusNotFound {
		t.Errorf("resetting twice: %d", rec.Code)
	}
	// Someone with no local account (an Entra user) has nothing to enrol.
	entra, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: uuid.NewString()}, time.Hour)
	if rec := b.do(http.MethodPost, "/v1/mfa/totp", entra, nil); rec.Code != http.StatusConflict || body(t, rec)["code"] != "mfa.local_accounts_only" {
		t.Errorf("an Entra user enrolling: %d %s", rec.Code, rec.Body.String())
	}
}
