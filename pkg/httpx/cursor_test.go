package httpx_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

func TestCursorRoundTrips(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 0, 0, 123456000, time.UTC)
	id := uuid.New()
	s := httpx.Cursor{At: at, ID: id}.Encode()
	c, ok, err := httpx.DecodeCursor(s)
	if err != nil || !ok || !c.At.Equal(at) || c.ID != id {
		t.Fatalf("%+v %v %v", c, ok, err)
	}
	if _, ok, err := httpx.DecodeCursor(""); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	for _, bad := range []string{"nope", "e30", "eyJ0IjoiMjAyNi0wMS0wMVQwMDowMDowMFoifQ"} {
		if _, _, err := httpx.DecodeCursor(bad); !errors.Is(err, httpx.ErrBadCursor) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	_ = errors.Is
}

func TestPageSize(t *testing.T) {
	n := 500
	zero := 0
	if httpx.PageSize(nil, 50, 200) != 50 || httpx.PageSize(&zero, 50, 200) != 50 || httpx.PageSize(&n, 50, 200) != 200 {
		t.Fatal("clamping")
	}
}
