package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The headers every delivery carries, as the Standard Webhooks
// specification (and Svix) name them, so a receiver can verify with any
// library that follows it.
const (
	// HeaderID is the message id: the same on every attempt and every
	// endpoint, so a receiver that has seen it ignores it (idempotency).
	HeaderID = "webhook-id"
	// HeaderTimestamp is when this attempt was signed, in Unix seconds.
	HeaderTimestamp = "webhook-timestamp"
	// HeaderSignature is one "v1,<base64 HMAC-SHA256>" per active secret,
	// separated by spaces: two while a rotated-out secret is still honoured.
	HeaderSignature = "webhook-signature"
)

// SecretPrefix starts every signing secret as it is shown to an admin.
const SecretPrefix = "whsec_"

// secretBytes is a signing secret's length: 256 bits, HMAC-SHA256's block
// of strength.
const secretBytes = 32

// NewSecret is a fresh signing secret: its key, and the form an admin
// copies into their receiver ("whsec_" and the key in base64).
func NewSecret() (key []byte, shown string, err error) {
	key = make([]byte, secretBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	return key, FormatSecret(key), nil
}

// FormatSecret is key as an admin sees it.
func FormatSecret(key []byte) string {
	return SecretPrefix + base64.StdEncoding.EncodeToString(key)
}

// ParseSecret is the key in a secret as FormatSecret shows it; the prefix
// may be left off.
func ParseSecret(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, SecretPrefix))
	if err != nil || len(key) == 0 {
		return nil, errors.New("webhook: not a signing secret")
	}
	return key, nil
}

// Signature is one signature of a delivery: HMAC-SHA256 under key over
// "<id>.<timestamp>.<body>", as "v1,<base64>". The id and the timestamp are
// signed with the body, so neither can be replayed with another.
func Signature(key []byte, id string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	mac.Write([]byte{'.'})
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Sign sets a delivery's headers on h: its id, the timestamp, and a
// signature under each key, newest first.
func Sign(h http.Header, id string, at time.Time, body []byte, keys ...[]byte) {
	ts := at.Unix()
	sigs := make([]string, 0, len(keys))
	for _, k := range keys {
		sigs = append(sigs, Signature(k, id, ts, body))
	}
	h.Set(HeaderID, id)
	h.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	h.Set(HeaderSignature, strings.Join(sigs, " "))
}

// Tolerance is how far a delivery's timestamp may be from the receiver's
// clock before Verify refuses it as a replay.
const Tolerance = 5 * time.Minute

// Errors Verify answers.
var (
	ErrNoSignature = errors.New("webhook: missing id, timestamp or signature")
	ErrTimestamp   = errors.New("webhook: timestamp too old or too new")
	ErrSignature   = errors.New("webhook: no signature matches")
)

// Verify is what a receiver written in Go runs on a delivery: nil when one
// of its signatures is body's under secret (as FormatSecret shows it), and
// its timestamp is within Tolerance of now.
func Verify(secret string, h http.Header, body []byte, now time.Time) error {
	key, err := ParseSecret(secret)
	if err != nil {
		return err
	}
	id, ts, sigs := h.Get(HeaderID), h.Get(HeaderTimestamp), h.Get(HeaderSignature)
	if id == "" || ts == "" || sigs == "" {
		return ErrNoSignature
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrTimestamp
	}
	if d := now.Sub(time.Unix(sec, 0)); d > Tolerance || d < -Tolerance {
		return fmt.Errorf("%w: %s", ErrTimestamp, d.Round(time.Second))
	}
	want := Signature(key, id, sec, body)
	for _, s := range strings.Fields(sigs) {
		if hmac.Equal([]byte(s), []byte(want)) {
			return nil
		}
	}
	return ErrSignature
}
