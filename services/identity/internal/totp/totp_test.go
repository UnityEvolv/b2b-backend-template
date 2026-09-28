package totp_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/totp"
)

// RFC 6238's test vectors, with the SHA-1 secret "12345678901234567890"
// and eight digits; ours are six, so the last six of each.
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, c := range []struct {
		at   int64
		code string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		got := totp.Code(secret, totp.Step(time.Unix(c.at, 0)))
		if got != c.code[2:] {
			t.Errorf("t=%d: %s, want %s", c.at, got, c.code[2:])
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	step := totp.Step(now)
	code := totp.Code(secret, step)
	// Right now, a step early, a step late: all fine, once each.
	if got, ok := totp.Verify(secret, code, now, 0); !ok || got != step {
		t.Errorf("now: %v %d", ok, got)
	}
	if _, ok := totp.Verify(secret, totp.Code(secret, step-1), now, 0); !ok {
		t.Error("previous step refused")
	}
	if _, ok := totp.Verify(secret, totp.Code(secret, step+1), now, 0); !ok {
		t.Error("next step refused")
	}
	if _, ok := totp.Verify(secret, totp.Code(secret, step-2), now, 0); ok {
		t.Error("two steps back accepted")
	}
	// A code is never accepted twice: after step was used, it and anything
	// earlier are refused.
	if _, ok := totp.Verify(secret, code, now, step); ok {
		t.Error("replayed code accepted")
	}
	if _, ok := totp.Verify(secret, totp.Code(secret, step-1), now, step); ok {
		t.Error("older code accepted after a newer one")
	}
	// Spaces are fine; a wrong code, a short one, a wrong secret are not.
	if _, ok := totp.Verify(secret, code[:3]+" "+code[3:], now, 0); !ok {
		t.Error("code with a space refused")
	}
	other, _ := totp.NewSecret()
	if _, ok := totp.Verify(other, code, now, 0); ok {
		t.Error("another secret's code accepted")
	}
	if _, ok := totp.Verify(secret, "12345", now, 0); ok {
		t.Error("five digits accepted")
	}
}

func TestURIAndEncoding(t *testing.T) {
	secret := []byte("12345678901234567890")
	uri := totp.URI(secret, "unityofis", "ada@example.com")
	want := "otpauth://totp/unityofis:ada@example.com?algorithm=SHA1&digits=6&issuer=unityofis&period=30&secret=" + totp.Encode(secret)
	if uri != want {
		t.Errorf("uri:\n%s\n%s", uri, want)
	}
	if decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(totp.Encode(secret)); err != nil || string(decoded) != string(secret) {
		t.Error("encoding does not round-trip")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := totp.NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != totp.RecoveryCodes || len(hashes) != len(codes) {
		t.Fatalf("%d codes, %d hashes", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Errorf("code %q", c)
		}
		seen[c] = true
		// Typed in caps, with spaces, without the dash: the same code.
		typed := strings.ToUpper(strings.ReplaceAll(c, "-", " "))
		if string(totp.HashRecovery(typed)) != string(hashes[i]) {
			t.Errorf("%q typed as %q does not match", c, typed)
		}
		if !totp.LooksLikeRecovery(typed) {
			t.Errorf("%q not recognised as a recovery code", typed)
		}
	}
	if totp.LooksLikeRecovery("123456") {
		t.Error("a six-digit code looks like a recovery code")
	}
}
