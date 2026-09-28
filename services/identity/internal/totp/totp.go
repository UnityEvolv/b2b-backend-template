// Package totp is RFC 6238 time-based one-time passwords, as authenticator
// apps make them (UO-68), and the recovery codes that stand in for a lost
// device. Nothing here needs a dependency: HMAC-SHA1, thirty-second steps,
// six digits is what every app speaks.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period is one time step.
	Period = 30 * time.Second
	// Digits in a code.
	Digits = 6
	// SecretLen is the secret's length in bytes: 160 bits, the RFC's
	// recommendation for SHA-1.
	SecretLen = 20
	// Skew is how many steps either side of now still count, for clocks
	// that drift and people who type slowly.
	Skew = 1
	// RecoveryCodes is how many a person gets; RecoveryLen the letters in
	// each half of one.
	RecoveryCodes = 10
	recoveryLen   = 5
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret is a fresh random secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Encode is the secret as an authenticator app takes it: base32, no padding.
func Encode(secret []byte) string { return encoding.EncodeToString(secret) }

// URI is the otpauth: link an app scans as a QR code. issuer is the
// product; account is what the app shows under the code, the email.
func URI(secret []byte, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", Encode(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Step is the time step a moment falls in.
func Step(at time.Time) int64 { return at.Unix() / int64(Period.Seconds()) }

// Code is the code for a step.
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, value%mod)
}

// Verify is whether code is right for a step within Skew of now, and which
// step it was for. A step at or before lastUsed is refused, so the same
// code is never accepted twice. Compared in constant time.
func Verify(secret []byte, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	current := Step(now)
	matched := int64(0)
	ok := false
	// Every candidate is checked, so timing says nothing about which one
	// matched.
	for delta := -int64(Skew); delta <= int64(Skew); delta++ {
		step := current + delta
		if subtle.ConstantTimeCompare([]byte(Code(secret, step)), []byte(code)) == 1 && step > lastUsed {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// NewRecoveryCodes is a fresh set, as shown to the person once, with the
// hashes to store.
func NewRecoveryCodes() (codes []string, hashes [][]byte, err error) {
	const letters = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o, 1/l/i
	for i := 0; i < RecoveryCodes; i++ {
		raw := make([]byte, recoveryLen*2)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		var b strings.Builder
		for j, r := range raw {
			if j == recoveryLen {
				b.WriteByte('-')
			}
			b.WriteByte(letters[int(r)%len(letters)])
		}
		code := b.String()
		codes = append(codes, code)
		hashes = append(hashes, HashRecovery(code))
	}
	return codes, hashes, nil
}

// HashRecovery is how a recovery code is stored and looked up: normalised
// (case, spaces, the dash) then hashed.
func HashRecovery(code string) []byte {
	n := strings.ToLower(strings.TrimSpace(code))
	n = strings.NewReplacer(" ", "", "-", "").Replace(n)
	sum := sha256.Sum256([]byte(n))
	return sum[:]
}

// LooksLikeRecovery is whether what was typed is a recovery code rather
// than a six-digit code.
func LooksLikeRecovery(code string) bool {
	n := strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code))
	return len(n) == recoveryLen*2
}
