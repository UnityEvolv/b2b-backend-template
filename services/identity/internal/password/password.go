// Package password hashes and checks passwords for local accounts.
//
// argon2id, in the standard encoded form, so a hash carries its own
// parameters and the parameters can change without a migration: a hash made
// with the old ones still checks, and the next set uses the new ones.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The parameters new hashes use. OWASP's first recommendation for
// argon2id: 64 MiB, one pass, four lanes.
const (
	memoryKiB = 64 * 1024
	passes    = 1
	lanes     = 4
	saltLen   = 16
	keyLen    = 32
)

// Policy: what a password must be. Length is what matters; composition
// rules make passwords worse, not better.
const (
	MinLength = 12
	MaxLength = 200
)

// ErrPolicy is a password the policy refuses; the message says why.
type ErrPolicy struct{ Reason string }

func (e *ErrPolicy) Error() string { return "password: " + e.Reason }

// Check is whether a candidate password may be set for email.
func Check(candidate, email string) error {
	switch {
	case len(candidate) < MinLength:
		return &ErrPolicy{Reason: fmt.Sprintf("at least %d characters", MinLength)}
	case len(candidate) > MaxLength:
		return &ErrPolicy{Reason: fmt.Sprintf("at most %d characters", MaxLength)}
	case strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(email)):
		return &ErrPolicy{Reason: "not your email address"}
	case strings.TrimSpace(candidate) == "":
		return &ErrPolicy{Reason: "not blank"}
	}
	return nil
}

// Hash is the encoded argon2id hash of a password with a fresh salt.
func Hash(candidate string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(candidate), salt, passes, memoryKiB, lanes, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memoryKiB, passes, lanes,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify is whether candidate is the password behind encoded. A malformed
// hash is an error, not a mismatch, so a bad row is noticed.
func Verify(encoded, candidate string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("password: not an argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("password: unknown argon2 version")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errors.New("password: unreadable parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("password: unreadable salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("password: unreadable hash")
	}
	// Parameters argon2 would refuse or that no hash of ours ever had.
	if t == 0 || p == 0 || m < 8*uint32(p) || len(salt) < 8 || len(want) < 16 {
		return false, errors.New("password: implausible parameters")
	}
	got := argon2.IDKey([]byte(candidate), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// Dummy is a hash to check a candidate against when there is no account,
// so a missing address costs the same time as a wrong password. Made once.
var Dummy = func() string {
	h, err := Hash("nobody-has-this-password")
	if err != nil {
		panic(err)
	}
	return h
}()
