package server_test

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// decode is a response body as a map.
func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if rec.Body.Len() == 0 {
		return nil
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON (%d): %q", rec.Code, rec.Body.String())
	}
	return out
}

// The story's "done when": a person sets a photo, time zone and working
// hours, and those persist, the same in every org.
func TestProfileFieldsPersistAcrossOrgs(t *testing.T) {
	f := newAPI(t)
	m := f.signIn(t, acme, "ada@example.com", "Ada", nil)
	other := f.signIn(t, globex, "ada@example.com", "Ada", nil)
	me := f.person(t, id(t, m, "user", "id"), acme.String(), id(t, m, "membership", "id"))
	elsewhere := f.person(t, id(t, m, "user", "id"), globex.String(), id(t, other, "membership", "id"))

	// Refusals: a blank display name, an offset for a zone, hours that end
	// before they start, a day twice.
	for _, bad := range []map[string]any{
		{"display_name": "   "},
		{"time_zone": "+05:30"},
		{"time_zone": "IST"},
		{"working_hours": map[string]any{"days": []string{"mon"}, "start": "17:00", "end": "09:00"}},
		{"working_hours": map[string]any{"days": []string{"mon", "mon"}, "start": "09:00", "end": "17:00"}},
		{"working_hours": map[string]any{"days": []string{}, "start": "09:00", "end": "17:00"}},
	} {
		if status, out := f.do(t, http.MethodPatch, "/v1/me/profile", me, bad); status != http.StatusBadRequest {
			t.Errorf("%v: %d %v", bad, status, out)
		}
	}
	// Set, and read back from the other org too.
	status, out := f.do(t, http.MethodPatch, "/v1/me/profile", me, map[string]any{
		"display_name": "Ada L.", "time_zone": "Asia/Kolkata",
		"working_hours": map[string]any{"days": []string{"mon", "tue", "wed", "thu", "fri"}, "start": "09:30", "end": "18:00"},
	})
	if status != http.StatusOK || out["display_name"] != "Ada L." || out["time_zone"] != "Asia/Kolkata" {
		t.Fatalf("update: %d %v", status, out)
	}
	_, got := f.do(t, http.MethodGet, "/v1/me", elsewhere, nil)
	user := got["user"].(map[string]any)
	wh, _ := user["working_hours"].(map[string]any)
	if user["display_name"] != "Ada L." || user["time_zone"] != "Asia/Kolkata" || wh == nil || wh["start"] != "09:30" || len(wh["days"].([]any)) != 5 {
		t.Errorf("from the other org: %v", user)
	}
	// Only the fields sent change; null clears one.
	f.do(t, http.MethodPatch, "/v1/me/profile", me, map[string]any{"display_name": nil})
	_, got = f.do(t, http.MethodGet, "/v1/me", me, nil)
	user = got["user"].(map[string]any)
	if user["display_name"] != nil || user["time_zone"] != "Asia/Kolkata" {
		t.Errorf("after clearing the display name: %v", user)
	}
	// Appearance follows the person: set from one org, read from the other.
	if status, _ := f.do(t, http.MethodPatch, "/v1/me/profile", me, map[string]any{"theme": "sepia"}); status != http.StatusBadRequest {
		t.Errorf("a theme that does not exist: %d", status)
	}
	f.do(t, http.MethodPatch, "/v1/me/profile", me, map[string]any{"theme": "dark", "language": "pt-BR"})
	_, got = f.do(t, http.MethodGet, "/v1/me", elsewhere, nil)
	prefs, _ := got["user"].(map[string]any)["preferences"].(map[string]any)
	if prefs["theme"] != "dark" || prefs["language"] != "pt-BR" {
		t.Errorf("preferences from the other org: %v", prefs)
	}
	f.do(t, http.MethodPatch, "/v1/me/profile", me, map[string]any{"language": nil})
	_, got = f.do(t, http.MethodGet, "/v1/me", me, nil)
	if prefs := got["user"].(map[string]any)["preferences"].(map[string]any); prefs["language"] != nil || prefs["theme"] != "dark" {
		t.Errorf("after clearing the language: %v", prefs)
	}
	// A service cannot edit a profile.
	if status, _ := f.do(t, http.MethodPatch, "/v1/me/profile", f.service(t, "identity"), map[string]any{"display_name": "x"}); status != http.StatusForbidden {
		t.Errorf("a service editing: %d", status)
	}

	// The photo: needs the bucket.
	if os.Getenv("TEST_S3_ENDPOINT") == "" {
		t.Skip("TEST_S3_ENDPOINT is not set: no bucket for photos")
	}
	upload := func(token string, field, contentType string, data []byte) (int, map[string]any) {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		hdr := make(map[string][]string)
		hdr["Content-Disposition"] = []string{`form-data; name="` + field + `"; filename="photo"`}
		hdr["Content-Type"] = []string{contentType}
		part, _ := w.CreatePart(hdr)
		part.Write(data)
		w.Close()
		req := httptest.NewRequest(http.MethodPut, "/v1/me/photo", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec.Code, decode(t, rec)
	}
	// A wide picture becomes a square photo with a signed link; the link
	// shows up from the other org; a new upload replaces it; delete removes it.
	img := image.NewRGBA(image.Rect(0, 0, 300, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 300; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 0, 255})
		}
	}
	var encoded bytes.Buffer
	png.Encode(&encoded, img)
	if status, out := upload(me, "photo", "text/plain", []byte("not a picture")); status != http.StatusBadRequest {
		t.Errorf("text as a photo: %d %v", status, out)
	}
	if status, out := upload(me, "photo", "image/png", []byte("garbage")); status != http.StatusBadRequest {
		t.Errorf("garbage as a photo: %d %v", status, out)
	}
	if status, out := upload(me, "file", "image/png", encoded.Bytes()); status != http.StatusBadRequest {
		t.Errorf("wrong part name: %d %v", status, out)
	}
	status, out = upload(me, "photo", "image/png", encoded.Bytes())
	first, _ := out["photo_url"].(string)
	if status != http.StatusOK || first == "" {
		t.Fatalf("upload: %d %v", status, out)
	}
	resp, err := http.Get(first)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching the photo: %v %v", err, resp)
	}
	stored, _, err := image.Decode(resp.Body)
	resp.Body.Close()
	if err != nil || stored.Bounds().Dx() != 512 || stored.Bounds().Dy() != 512 {
		t.Errorf("stored photo: %v %v", err, stored.Bounds())
	}
	_, got = f.do(t, http.MethodGet, "/v1/me", elsewhere, nil)
	if url, _ := got["user"].(map[string]any)["photo_url"].(string); !strings.Contains(url, "profile-photo") {
		t.Errorf("photo from the other org: %v", got["user"])
	}
	status, out = upload(me, "photo", "image/png", encoded.Bytes())
	second, _ := out["photo_url"].(string)
	if status != http.StatusOK || second == "" || strings.Split(second, "?")[0] == strings.Split(first, "?")[0] {
		t.Errorf("second upload: %d %v", status, out)
	}
	if resp, err := http.Get(first); err == nil && resp.StatusCode == http.StatusOK {
		t.Error("the first photo is still there")
	}
	if status, _ := f.do(t, http.MethodDelete, "/v1/me/photo", me, nil); status != http.StatusNoContent {
		t.Errorf("delete: %d", status)
	}
	_, got = f.do(t, http.MethodGet, "/v1/me", me, nil)
	if got["user"].(map[string]any)["photo_url"] != nil {
		t.Errorf("after deleting: %v", got["user"])
	}
	if status, _ := f.do(t, http.MethodDelete, "/v1/me/photo", me, nil); status != http.StatusNoContent {
		t.Errorf("deleting twice: %d", status)
	}
}
