package server_test

import (
	"archive/zip"
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/server"
)

// frameFakes is the bucket, with pre-signed uploads: the objects are the
// offboarding fakes', so an export finds the frame images too.
type frameFakes struct{ *offFakes }

func (f frameFakes) UploadURL(_ context.Context, _ string, key storage.Key, _ string, _ int64, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://files.test/upload/" + key.String())
}

// upload is the browser's PUT to a pre-signed link.
func (f frameFakes) upload(key string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
}

// framePNG is a w×h PNG; transparent leaves its middle clear, as a frame's is.
func framePNG(t *testing.T, w, h int, transparent bool) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	border := color.NRGBA{R: 200, G: 30, B: 30, A: 255}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			edge := x < 40 || y < 40 || x >= w-40 || y >= h-40
			if edge || !transparent {
				img.SetNRGBA(x, y, border)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// framesSetup is an org in zone with an Admin, a User and the fakes wired.
type framesSetup struct {
	h                     http.Handler
	srv                   *server.Server
	recorder              *memoryRecorder
	cluster               *db.Cluster
	fakes                 frameFakes
	clock                 *clockT
	orgID                 string
	operator, admin, user string
	owner                 string
	ownerUser             uuid.UUID
	otherOrg, otherAdmin  string
	adminPath, activePath string
}

func newFrames(t *testing.T, zone string) *framesSetup {
	t.Helper()
	h, cluster, issuer, srv, recorder := newAPIAudited(t)
	fakes := frameFakes{newOffFakes()}
	clock := &clockT{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	srv.WithOffboarding(server.Offboarding{Platform: fakes, Data: fakes, Files: fakes, Services: offServices, Now: clock.now}).WithFrames(fakes)
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": zone})["org_id"].(string)
	other := create(t, h, operator, map[string]any{"name": "Globex", "time_zone": "UTC"})["org_id"].(string)
	owner, admin, user, otherAdmin := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	grants[orgID+"/"+owner] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	grants[orgID+"/"+admin] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	grants[orgID+"/"+user] = authz.Grant{Role: authz.User, Permissions: authz.Effective(authz.User, authz.Defaults())}
	grants[other+"/"+otherAdmin] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	ownerUser := uuid.New()
	ownerToken, err := issuer.Issue(auth.Caller{UserID: ownerUser.String(), OrgID: orgID, MembershipID: owner}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &framesSetup{
		h: h, srv: srv, recorder: recorder, cluster: cluster, fakes: fakes, clock: clock, orgID: orgID,
		operator: operator, admin: tokenForMember(t, issuer, orgID, admin), user: tokenForMember(t, issuer, orgID, user),
		owner: ownerToken, ownerUser: ownerUser,
		otherOrg: other, otherAdmin: tokenForMember(t, issuer, other, otherAdmin),
		adminPath: "/v1/organizations/" + orgID + "/frames", activePath: "/v1/organizations/" + orgID + "/frame",
	}
}

// active is the frame showing on date ("" for today), or nil.
func (f *framesSetup) active(t *testing.T, date string) (map[string]any, map[string]any) {
	t.Helper()
	path := f.activePath
	if date != "" {
		path += "?date=" + date
	}
	status, body := get(t, f.h, path, f.user)
	if status != http.StatusOK {
		t.Fatalf("active frame %s: %d %v", date, status, body)
	}
	frame, _ := body["frame"].(map[string]any)
	return frame, body
}

func (f *framesSetup) set(t *testing.T, key string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return do(t, f.h, http.MethodPut, f.adminPath+"/"+key, f.admin, body, "")
}

func frameKey(frame map[string]any) string {
	if frame == nil {
		return ""
	}
	if k, ok := frame["key"].(string); ok {
		return k
	}
	return "org:" + frame["id"].(string)
}

// With nothing set, every platform frame with dates is on with them;
// celebration, which has none, is off; and the images are the web app's
// static paths.
func TestFrameDefaults(t *testing.T) {
	f := newFrames(t, "UTC")
	status, body := get(t, f.h, f.adminPath, f.admin)
	if status != http.StatusOK || body["decorations_enabled"] != true || body["time_zone"] != "UTC" {
		t.Fatalf("settings: %d %v", status, body)
	}
	frames := body["platform_frames"].([]any)
	if len(frames) != 8 {
		t.Fatalf("platform frames: %v", frames)
	}
	byKey := map[string]map[string]any{}
	for _, x := range frames {
		m := x.(map[string]any)
		byKey[m["key"].(string)] = m
	}
	christmas := byKey["christmas"]
	if christmas["enabled"] != true || christmas["start_md"] != "12-20" || christmas["end_md"] != "12-26" || christmas["customized"] != false ||
		christmas["default_start_md"] != "12-20" || christmas["enabled_at"] != nil {
		t.Errorf("christmas: %v", christmas)
	}
	imgs := christmas["images"].(map[string]any)
	if l := imgs["portrait"].(map[string]any); l["light"] != "/frames/christmas-portrait-light.svg" || l["dark"] != "/frames/christmas-portrait-dark.svg" {
		t.Errorf("christmas images: %v", imgs)
	}
	if c := byKey["celebration"]; c["enabled"] != false || c["start_md"] != nil || c["default_start_md"] != nil {
		t.Errorf("celebration: %v", c)
	}
	if len(body["org_frames"].([]any)) != 0 {
		t.Errorf("org frames: %v", body["org_frames"])
	}

	for date, want := range map[string]string{
		"2026-12-25": "christmas", "2026-07-01": "", "2026-10-22": "diwali", "2026-10-30": "halloween",
		"2026-03-14": "holi", "2026-04-04": "easter", "2026-03-31": "eid",
	} {
		frame, _ := f.active(t, date)
		if got := frameKey(frame); got != want {
			t.Errorf("%s: %q, want %q", date, got, want)
		}
	}
	frame, _ := f.active(t, "2026-12-25")
	if frame["kind"] != "platform" || frame["name"] != "Christmas" || frame["icon"] != "tree" ||
		frame["start_date"] != "2026-12-20" || frame["end_date"] != "2026-12-26" {
		t.Errorf("christmas showing: %v", frame)
	}
	if l := frame["images"].(map[string]any)["landscape"].(map[string]any); l["light"] != "/frames/christmas-landscape-light.svg" {
		t.Errorf("christmas showing images: %v", frame["images"])
	}
}

// New Year wraps the year: 31 December to 2 January, one showing.
func TestFrameNewYearWraps(t *testing.T) {
	f := newFrames(t, "UTC")
	for _, c := range []struct{ date, start, end string }{
		{"2026-12-31", "2026-12-31", "2027-01-02"},
		{"2027-01-01", "2026-12-31", "2027-01-02"},
		{"2027-01-02", "2026-12-31", "2027-01-02"},
	} {
		frame, _ := f.active(t, c.date)
		if frameKey(frame) != "new_year" || frame["start_date"] != c.start || frame["end_date"] != c.end {
			t.Errorf("%s: %v", c.date, frame)
		}
	}
	if frame, _ := f.active(t, "2027-01-03"); frame != nil {
		t.Errorf("3 January: %v", frame)
	}
	// An org's own wrapping dates work the same way.
	if status, out := f.set(t, "new_year", map[string]any{"enabled": true, "start_md": "12-28", "end_md": "01-05"}); status != http.StatusOK || out["customized"] != true {
		t.Fatalf("new dates: %d %v", status, out)
	}
	if frame, _ := f.active(t, "2027-01-05"); frameKey(frame) != "new_year" || frame["start_date"] != "2026-12-28" {
		t.Errorf("5 January: %v", frame)
	}
	if frame, _ := f.active(t, "2026-12-26"); frameKey(frame) != "christmas" {
		t.Errorf("26 December: %v", frame)
	}
}

// Diwali on the org's own dates shows from midnight in the org's zone, not UTC's.
func TestFrameCustomDatesInOrgZone(t *testing.T) {
	f := newFrames(t, "Asia/Kolkata")
	status, out := f.set(t, "diwali", map[string]any{"enabled": true, "start_md": "11-08", "end_md": "11-10"})
	if status != http.StatusOK || out["start_md"] != "11-08" || out["end_md"] != "11-10" || out["customized"] != true || out["enabled"] != true {
		t.Fatalf("diwali: %d %v", status, out)
	}
	// 23:30 on 7 November in Kolkata: not yet.
	f.clock.t = time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	if frame, body := f.active(t, ""); frame != nil || body["date"] != "2026-11-07" {
		t.Errorf("before midnight: %v", body)
	}
	// 00:30 on 8 November in Kolkata, still the 7th in UTC.
	f.clock.t = time.Date(2026, 11, 7, 19, 0, 0, 0, time.UTC)
	frame, body := f.active(t, "")
	if frameKey(frame) != "diwali" || body["date"] != "2026-11-08" || frame["start_date"] != "2026-11-08" || frame["end_date"] != "2026-11-10" {
		t.Errorf("after midnight: %v", body)
	}
	// The default dates no longer apply.
	if frame, _ := f.active(t, "2026-10-21"); frame != nil {
		t.Errorf("the default dates still show: %v", frame)
	}
	// Changing the dates is audited, turning it on was not (it was on).
	if !f.recorder.has("organization.frame_dates_changed") || f.recorder.has("organization.frame_enabled") {
		t.Errorf("audit: %v", f.recorder.actions())
	}
	// Back to the defaults with nulls.
	if status, out := f.set(t, "diwali", map[string]any{"enabled": true, "start_md": nil, "end_md": nil}); status != http.StatusOK || out["start_md"] != "10-20" || out["customized"] != false {
		t.Errorf("reset: %d %v", status, out)
	}
	// Left out keeps what is there.
	f.set(t, "diwali", map[string]any{"enabled": true, "start_md": "11-01", "end_md": "11-02"})
	if status, out := f.set(t, "diwali", map[string]any{"enabled": false}); status != http.StatusOK || out["start_md"] != "11-01" || out["enabled"] != false {
		t.Errorf("turned off: %d %v", status, out)
	}
	if !f.recorder.has("organization.frame_disabled") {
		t.Errorf("turning off is not audited: %v", f.recorder.actions())
	}
	if frame, _ := f.active(t, "2026-11-01"); frame != nil {
		t.Errorf("a frame turned off shows: %v", frame)
	}
}

// Where two platform frames overlap, the one most recently turned on shows.
func TestFrameMostRecentlyEnabledWins(t *testing.T) {
	f := newFrames(t, "UTC")
	// Celebration has no dates of its own: it cannot be turned on without them.
	if status, out := f.set(t, "celebration", map[string]any{"enabled": true}); status != http.StatusBadRequest || out["code"] != "frame.needs_dates" {
		t.Errorf("celebration without dates: %d %v", status, out)
	}
	f.clock.add(time.Hour)
	if status, out := f.set(t, "celebration", map[string]any{"enabled": true, "start_md": "12-24", "end_md": "12-25"}); status != http.StatusOK || out["enabled_at"] == nil {
		t.Fatalf("celebration: %d %v", status, out)
	}
	if !f.recorder.has("organization.frame_enabled") {
		t.Errorf("turning on is not audited: %v", f.recorder.actions())
	}
	if frame, _ := f.active(t, "2026-12-25"); frameKey(frame) != "celebration" {
		t.Errorf("celebration, turned on, over christmas, on by default: %v", frame)
	}
	if frame, _ := f.active(t, "2026-12-23"); frameKey(frame) != "christmas" {
		t.Errorf("only christmas: %v", frame)
	}
	// Christmas turned off and on again, later: it is now the most recent.
	f.clock.add(time.Hour)
	f.set(t, "christmas", map[string]any{"enabled": false})
	f.clock.add(time.Hour)
	f.set(t, "christmas", map[string]any{"enabled": true})
	if frame, _ := f.active(t, "2026-12-25"); frameKey(frame) != "christmas" {
		t.Errorf("christmas, turned on last: %v", frame)
	}
}

// The one switch: off, and nothing shows, whatever each frame says.
func TestDecorationsOff(t *testing.T) {
	f := newFrames(t, "UTC")
	path := "/v1/organizations/" + f.orgID + "/decorations"
	if status, _ := do(t, f.h, http.MethodPut, path, f.user, map[string]any{"enabled": false}, ""); status != http.StatusForbidden {
		t.Errorf("a User switching decorations: %d", status)
	}
	if status, out := do(t, f.h, http.MethodPut, path, f.admin, map[string]any{"enabled": false}, ""); status != http.StatusOK || out["enabled"] != false {
		t.Fatalf("off: %d %v", status, out)
	}
	if frame, body := f.active(t, "2026-12-25"); frame != nil || body["frame"] != nil {
		t.Errorf("decorations off, a frame shows: %v", body)
	}
	if _, body := get(t, f.h, f.adminPath, f.admin); body["decorations_enabled"] != false {
		t.Errorf("settings: %v", body)
	}
	if !f.recorder.has("organization.decorations_toggled") {
		t.Errorf("not audited: %v", f.recorder.actions())
	}
	do(t, f.h, http.MethodPut, path, f.admin, map[string]any{"enabled": true}, "")
	if frame, _ := f.active(t, "2026-12-25"); frameKey(frame) != "christmas" {
		t.Errorf("back on: %v", frame)
	}
}

// What the admin page would not offer, the API refuses: bad dates, unknown
// frames, and anyone but an admin of this org.
func TestFrameRefusals(t *testing.T) {
	f := newFrames(t, "UTC")
	for _, body := range []map[string]any{
		{"enabled": true, "start_md": "13-01", "end_md": "01-02"},
		{"enabled": true, "start_md": "1-5", "end_md": "01-06"},
		{"enabled": true, "start_md": "02-30", "end_md": "03-01"},
		{"enabled": true, "start_md": "10-01"},
		{"enabled": true, "start_md": "10-01", "end_md": nil},
	} {
		if status, out := f.set(t, "diwali", body); status != http.StatusBadRequest || out["fields"] == nil {
			t.Errorf("%v: %d %v", body, status, out)
		}
	}
	if status, out := f.set(t, "diwali", map[string]any{"enabled": true, "start_md": "02-29", "end_md": "03-01"}); status != http.StatusOK {
		t.Errorf("29 February is a date: %d %v", status, out)
	}
	if status, out := f.set(t, "thanksgiving", map[string]any{"enabled": true}); status != http.StatusNotFound || out["code"] != "frame.not_found" {
		t.Errorf("an unknown frame: %d %v", status, out)
	}
	// A User may see the frame showing, not change or list the settings.
	if status, _ := do(t, f.h, http.MethodPut, f.adminPath+"/diwali", f.user, map[string]any{"enabled": false}, ""); status != http.StatusForbidden {
		t.Errorf("a User changing a frame: %d", status)
	}
	if status, _ := get(t, f.h, f.adminPath, f.user); status != http.StatusForbidden {
		t.Errorf("a User reading the settings: %d", status)
	}
	if status, _ := do(t, f.h, http.MethodPost, f.adminPath+"/uploads", f.user, map[string]any{"files": []any{}}, ""); status != http.StatusForbidden {
		t.Errorf("a User asking for uploads: %d", status)
	}
	if status, _ := get(t, f.h, f.activePath, f.user); status != http.StatusOK {
		t.Errorf("a User reading the frame showing: %d", status)
	}
	// Another org's admin reaches nothing here.
	if status, _ := get(t, f.h, f.activePath, f.otherAdmin); status != http.StatusForbidden {
		t.Errorf("another org reading the frame: %d", status)
	}
	if status, _ := do(t, f.h, http.MethodPut, f.adminPath+"/diwali", f.otherAdmin, map[string]any{"enabled": false}, ""); status != http.StatusForbidden {
		t.Errorf("another org changing a frame: %d", status)
	}
	// A platform operator may.
	if status, _ := get(t, f.h, f.adminPath, f.operator); status != http.StatusOK {
		t.Errorf("an operator reading the settings: %d", status)
	}
	if status, out := get(t, f.h, f.activePath+"?date=2026-13-01", f.user); status != http.StatusBadRequest || out["code"] != httpx.CodeInvalidRequest {
		t.Errorf("a bad date: %d %v", status, out)
	}
}

// uploadFrame asks for links, uploads data for each shape's light image
// (and dark for landscape), and returns the keys to create with.
func (f *framesSetup) uploadFrame(t *testing.T, data map[string][]byte) map[string]any {
	t.Helper()
	files := []any{}
	order := []string{"landscape/light", "square/light", "portrait/light", "landscape/dark"}
	for _, k := range order {
		shape, variant, _ := strings.Cut(k, "/")
		files = append(files, map[string]any{"shape": shape, "variant": variant, "content_type": "image/png", "size": len(data[k])})
	}
	status, out := do(t, f.h, http.MethodPost, f.adminPath+"/uploads", f.admin, map[string]any{"files": files}, "")
	if status != http.StatusOK {
		t.Fatalf("uploads: %d %v", status, out)
	}
	images := map[string]any{"landscape": map[string]any{}, "square": map[string]any{}, "portrait": map[string]any{}}
	for i, u := range out["uploads"].([]any) {
		up := u.(map[string]any)
		key := up["key"].(string)
		if !strings.HasPrefix(key, "orgs/"+f.orgID+"/office-frame/") || !strings.HasPrefix(up["upload_url"].(string), "https://files.test/upload/") ||
			up["content_type"] != "image/png" || up["expires_at"] == nil {
			t.Fatalf("upload: %v", up)
		}
		f.fakes.upload(key, data[order[i]])
		images[up["shape"].(string)].(map[string]any)[up["variant"].(string)] = key
	}
	return images
}

func goodFrameImages(t *testing.T) map[string][]byte {
	landscape := framePNG(t, 1920, 1080, true)
	return map[string][]byte{
		"landscape/light": landscape, "landscape/dark": landscape,
		"square/light": framePNG(t, 1080, 1080, true), "portrait/light": framePNG(t, 1080, 1440, true),
	}
}

// An org's own frame: uploaded, checked, created once per key, shown over
// any platform frame on its dates, exported, and removed with its images.
func TestOrgFrame(t *testing.T) {
	f := newFrames(t, "UTC")
	images := f.uploadFrame(t, goodFrameImages(t))
	body := map[string]any{"name": "Founders' Day", "icon": "star", "start_date": "2026-12-24", "end_date": "2026-12-26", "images": images}
	status, created := do(t, f.h, http.MethodPost, f.adminPath, f.admin, body, "k1")
	if status != http.StatusCreated || created["name"] != "Founders' Day" || created["icon"] != "star" || created["start_date"] != "2026-12-24" {
		t.Fatalf("create: %d %v", status, created)
	}
	imgs := created["images"].(map[string]any)
	landscape := imgs["landscape"].(map[string]any)
	if !strings.HasPrefix(landscape["light"].(string), "https://files.test/orgs/"+f.orgID+"/office-frame/") || landscape["dark"] == nil {
		t.Errorf("landscape: %v", landscape)
	}
	if square := imgs["square"].(map[string]any); square["dark"] != nil {
		t.Errorf("square has no dark image: %v", square)
	}
	// A retry answers with the same frame; the key for another frame is refused.
	if status, again := do(t, f.h, http.MethodPost, f.adminPath, f.admin, body, "k1"); status != http.StatusCreated || again["id"] != created["id"] {
		t.Errorf("retry: %d %v", status, again)
	}
	other := map[string]any{"name": "Other", "start_date": "2026-12-24", "end_date": "2026-12-26", "images": images}
	if status, out := do(t, f.h, http.MethodPost, f.adminPath, f.admin, other, "k1"); status != http.StatusConflict || out["code"] != "request.idempotency_key_reused" {
		t.Errorf("reused key: %d %v", status, out)
	}
	if !f.recorder.has("organization.frame_created") {
		t.Errorf("not audited: %v", f.recorder.actions())
	}

	// On its dates it beats Christmas, even one turned on since.
	f.clock.add(time.Hour)
	f.set(t, "christmas", map[string]any{"enabled": false})
	f.set(t, "christmas", map[string]any{"enabled": true})
	frame, _ := f.active(t, "2026-12-25")
	if frame["kind"] != "organization" || frame["id"] != created["id"] || frame["key"] != nil || frame["name"] != "Founders' Day" {
		t.Errorf("on its dates: %v", frame)
	}
	if frame, _ := f.active(t, "2026-12-26"); frameKey(frame) != "org:"+created["id"].(string) {
		t.Errorf("its last day: %v", frame)
	}
	if frame, _ := f.active(t, "2026-12-27"); frameKey(frame) != "" {
		t.Errorf("after it, before new year: %v", frame)
	}
	if frame, _ := f.active(t, "2027-12-25"); frameKey(frame) != "christmas" {
		t.Errorf("it does not repeat: %v", frame)
	}
	// Listed for the admin.
	if _, s := get(t, f.h, f.adminPath, f.admin); len(s["org_frames"].([]any)) != 1 {
		t.Errorf("settings: %v", s)
	}

	// The export carries the frames and their images.
	f.fakes.emails[f.ownerUser] = "owner@acme.test"
	if status, out := do(t, f.h, http.MethodPost, "/v1/organizations/"+f.orgID+"/exports", f.owner, nil, "e1"); status != http.StatusAccepted {
		t.Fatalf("export: %d %v", status, out)
	}
	if err := f.srv.RunExports(t.Context()); err != nil {
		t.Fatal(err)
	}
	var archive []byte
	f.fakes.mu.Lock()
	for k, v := range f.fakes.objects {
		if strings.Contains(k, "/data-export/") {
			archive = v
		}
	}
	f.fakes.mu.Unlock()
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	names := map[string]bool{}
	for _, zf := range z.File {
		names[zf.Name] = true
	}
	id := created["id"].(string)
	for _, want := range []string{"organization/files/frames/" + id + "/landscape-light.png", "organization/files/frames/" + id + "/landscape-dark.png", "organization/files/frames/" + id + "/portrait-light.png"} {
		if !names[want] {
			t.Errorf("archive without %s: %v", want, names)
		}
	}

	// Removed, with its images.
	before := len(f.fakes.objects)
	if status, _ := do(t, f.h, http.MethodDelete, f.adminPath+"/org/"+id, f.user, nil, ""); status != http.StatusForbidden {
		t.Errorf("a User removing a frame: %d", status)
	}
	if status, _ := do(t, f.h, http.MethodDelete, f.adminPath+"/org/"+id, f.admin, nil, ""); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if after := len(f.fakes.objects); before-after != 4 {
		t.Errorf("images removed: %d", before-after)
	}
	if status, _ := do(t, f.h, http.MethodDelete, f.adminPath+"/org/"+id, f.admin, nil, ""); status != http.StatusNotFound {
		t.Errorf("deleting twice: %d", status)
	}
	if !f.recorder.has("organization.frame_deleted") {
		t.Errorf("not audited: %v", f.recorder.actions())
	}
	if frame, _ := f.active(t, "2026-12-25"); frameKey(frame) != "christmas" {
		t.Errorf("after removal: %v", frame)
	}
}

// An image that is opaque, of another shape, not uploaded, another org's, or
// not a PNG or WebP is refused, naming each one.
func TestOrgFrameImageRefusals(t *testing.T) {
	f := newFrames(t, "UTC")
	create := func(data map[string][]byte, mutate func(map[string]any)) (int, map[string]any) {
		images := f.uploadFrame(t, data)
		if mutate != nil {
			mutate(images)
		}
		return do(t, f.h, http.MethodPost, f.adminPath, f.admin, map[string]any{"name": "X", "start_date": "2026-05-01", "end_date": "2026-05-02", "images": images}, uuid.NewString())
	}
	opaque := goodFrameImages(t)
	opaque["square/light"] = framePNG(t, 1080, 1080, false)
	if status, out := create(opaque, nil); status != http.StatusBadRequest || out["code"] != "image.not_transparent" || out["fields"].(map[string]any)["images.square.light"] == nil {
		t.Errorf("opaque: %d %v", status, out)
	}
	wrong := goodFrameImages(t)
	wrong["portrait/light"] = framePNG(t, 1080, 1920, true) // 9:16, not the canvas's 3:4
	if status, out := create(wrong, nil); status != http.StatusBadRequest || out["code"] != "image.wrong_shape" || out["fields"].(map[string]any)["images.portrait.light"] == nil {
		t.Errorf("wrong shape: %d %v", status, out)
	}
	notImage := goodFrameImages(t)
	notImage["landscape/light"] = []byte("GIF89a not really")
	if status, out := create(notImage, nil); status != http.StatusBadRequest || out["code"] != "image.unsupported" {
		t.Errorf("not an image: %d %v", status, out)
	}
	if status, out := create(goodFrameImages(t), func(images map[string]any) {
		images["square"].(map[string]any)["light"] = "orgs/" + f.otherOrg + "/office-frame/" + uuid.NewString()
	}); status != http.StatusBadRequest || out["code"] != "image.not_uploaded" {
		t.Errorf("another org's key: %d %v", status, out)
	}
	if status, out := create(goodFrameImages(t), func(images map[string]any) {
		images["square"].(map[string]any)["light"] = "orgs/" + f.orgID + "/office-frame/" + uuid.NewString()
	}); status != http.StatusBadRequest || out["code"] != "image.not_uploaded" {
		t.Errorf("never uploaded: %d %v", status, out)
	}
	if status, out := create(goodFrameImages(t), func(images map[string]any) { delete(images, "portrait") }); status != http.StatusBadRequest || out["fields"].(map[string]any)["images.portrait.light"] == nil {
		t.Errorf("a shape left out: %d %v", status, out)
	}
	if status, out := do(t, f.h, http.MethodPost, f.adminPath, f.admin, map[string]any{"name": "X", "start_date": "2026-05-02", "end_date": "2026-05-01", "images": map[string]any{}}, "k"); status != http.StatusBadRequest || out["fields"].(map[string]any)["end_date"] == nil {
		t.Errorf("end before start: %d %v", status, out)
	}
	if status, _ := do(t, f.h, http.MethodPost, f.adminPath, f.admin, map[string]any{"name": "X", "start_date": "2026-05-01", "end_date": "2026-05-02", "images": map[string]any{}}, ""); status != http.StatusBadRequest {
		t.Errorf("no idempotency key: %d", status)
	}
	// The uploads themselves: PNG or WebP within 5 MB, each once.
	for _, files := range [][]any{
		{map[string]any{"shape": "landscape", "variant": "light", "content_type": "image/jpeg", "size": 100}},
		{map[string]any{"shape": "landscape", "variant": "light", "content_type": "image/png", "size": 6 << 20}},
		{map[string]any{"shape": "wide", "variant": "light", "content_type": "image/png", "size": 100}},
		{map[string]any{"shape": "square", "variant": "light", "content_type": "image/png", "size": 100}, map[string]any{"shape": "square", "variant": "light", "content_type": "image/png", "size": 100}},
		{},
	} {
		if status, out := do(t, f.h, http.MethodPost, f.adminPath+"/uploads", f.admin, map[string]any{"files": files}, ""); status != http.StatusBadRequest {
			t.Errorf("uploads %v: %d %v", files, status, out)
		}
	}
	if _, s := get(t, f.h, f.adminPath, f.admin); len(s["org_frames"].([]any)) != 0 {
		t.Errorf("a refused frame was kept: %v", s["org_frames"])
	}
}

// The org's frame rows go with it when it is purged.
func TestFramesPurged(t *testing.T) {
	f := newFrames(t, "UTC")
	f.set(t, "diwali", map[string]any{"enabled": false})
	images := f.uploadFrame(t, goodFrameImages(t))
	if status, out := do(t, f.h, http.MethodPost, f.adminPath, f.admin, map[string]any{"name": "X", "start_date": "2026-05-01", "end_date": "2026-05-02", "images": images}, "k"); status != http.StatusCreated {
		t.Fatalf("create: %d %v", status, out)
	}
	if status, out := do(t, f.h, http.MethodPost, "/v1/organizations/"+f.orgID+"/close", f.operator, map[string]any{"confirm_name": "Acme", "reason": "test"}, ""); status != http.StatusOK {
		t.Fatalf("close: %d %v", status, out)
	}
	f.clock.add(31 * 24 * time.Hour)
	if err := f.srv.RunPurges(t.Context()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	ctx := db.WithActor(t.Context(), db.SystemActor("organization"))
	var left int
	if err := f.cluster.Read(ctx, f.orgID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM org_frames WHERE org_id = $1) + (SELECT count(*) FROM org_frame_settings WHERE org_id = $1)`, f.orgID).Scan(&left)
	}); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d frame rows left after the purge", left)
	}
}
