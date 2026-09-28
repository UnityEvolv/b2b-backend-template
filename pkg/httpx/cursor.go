package httpx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Cursor pagination, never offset: a page ends with an opaque cursor that
// names the last row seen (its time and id), and the next page starts after
// it. Stable under inserts, and the client never sees the shape.
type Cursor struct {
	At time.Time `json:"t,omitzero"`
	ID uuid.UUID `json:"i"`
	// Key is the sort value when a list is ordered by a string, such as a
	// name, rather than a time.
	Key string `json:"k,omitempty"`
}

// Encode is the opaque form.
func (c Cursor) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ErrBadCursor means the cursor was not one this service issued.
var ErrBadCursor = errors.New("bad cursor")

// DecodeCursor is the cursor behind an opaque string. Empty means the first page.
func DecodeCursor(s string) (Cursor, bool, error) {
	if s == "" {
		return Cursor{}, false, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, false, ErrBadCursor
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil || c.ID == uuid.Nil || (c.At.IsZero() && c.Key == "") {
		return Cursor{}, false, ErrBadCursor
	}
	return c, true, nil
}

// PageSize clamps a requested page size to [1, max], defaulting when unset.
func PageSize(requested *int, def, max int) int {
	if requested == nil || *requested <= 0 {
		return def
	}
	if *requested > max {
		return max
	}
	return *requested
}
