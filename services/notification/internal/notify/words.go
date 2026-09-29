package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func str(data map[string]any, key, fallback string) string {
	if v, ok := data[key].(string); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

// Words is what a push or an email says for an event of kind: a title and a
// line. count above one is a batch. The apps word the feed themselves from
// the same data; these are for the places the apps are not.
func Words(kind string, data map[string]any, count int) (string, string) {
	by := str(data, "by", "Someone")
	where := str(data, "where", "")
	in := ""
	if where != "" {
		in = " in " + where
	}
	switch kind {
	case "mention":
		if count > 1 {
			return fmt.Sprintf("%d new mentions%s", count, in), "Open the conversation to catch up."
		}
		return by + " mentioned you" + in, "Open the conversation to reply."
	case "direct_message":
		if count > 1 {
			return fmt.Sprintf("%d new messages from %s", count, by), "Open the conversation to reply."
		}
		return "New message from " + by, "Open the conversation to reply."
	case "room_message":
		if count > 1 {
			return fmt.Sprintf("%d new messages%s", count, in), "Open the room's conversation to catch up."
		}
		return "New message" + in, by + " wrote in the room."
	case "knock":
		return by + " is knocking", "At " + str(data, "room", "your room") + "."
	case "admit":
		return "You were let in", "You can go into " + str(data, "room", "the room") + " now."
	case "guest_arrived":
		return str(data, "guest", "Your guest") + " has arrived", "In " + str(data, "room", "the office") + "."
	case "call_started":
		return "A call started" + in, by + " started a call."
	case "test":
		return "Notifications are working", "This is the test you asked for."
	}
	return str(data, "heading", "Something needs your attention"), str(data, "line", "Open the app to see it.")
}

// UnsubscribeToken is a link that turns off one category's email for one
// person, signed so it needs no sign-in and cannot be made for anyone else.
func UnsubscribeToken(key []byte, org, membership uuid.UUID, category Category) string {
	body := org.String() + "." + membership.String() + "." + string(category)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// ErrBadToken means an unsubscribe token was not one of ours.
var ErrBadToken = errors.New("not an unsubscribe token")

// ParseUnsubscribe is the person and category behind a token.
func ParseUnsubscribe(key []byte, token string) (uuid.UUID, uuid.UUID, Category, error) {
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
	category := Category(parts[2])
	if err1 != nil || err2 != nil || !category.Valid() {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	if !hmac.Equal([]byte(UnsubscribeToken(key, org, membership, category)), []byte(head+"."+sig)) {
		return uuid.Nil, uuid.Nil, "", ErrBadToken
	}
	return org, membership, category, nil
}
