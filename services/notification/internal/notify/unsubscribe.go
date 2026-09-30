package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// UnsubscribeToken is a link that turns off one category's email (or, for
// notifycat.DigestToken, the digest) for one person, signed so it needs no
// sign-in and cannot be made for anyone else.
func UnsubscribeToken(key []byte, org, membership uuid.UUID, category string) string {
	body := org.String() + "." + membership.String() + "." + category
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// ErrBadToken means an unsubscribe token was not one of ours.
var ErrBadToken = errors.New("not an unsubscribe token")

// ParseUnsubscribe is the person and category behind a token: a category
// id, or notifycat.DigestToken for the digest. Whether the category is
// still registered is the caller's to check.
func ParseUnsubscribe(key []byte, token string) (uuid.UUID, uuid.UUID, string, error) {
	head, sig, ok := strings.Cut(token, ".")
	if !ok || len(key) == 0 {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	org, err1 := uuid.Parse(parts[0])
	membership, err2 := uuid.Parse(parts[1])
	category := parts[2]
	if err1 != nil || err2 != nil || category == "" {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	if !hmac.Equal([]byte(UnsubscribeToken(key, org, membership, category)), []byte(head+"."+sig)) {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	return org, membership, category, nil
}
