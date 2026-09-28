package server

import (
	"fmt"
	"regexp"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Festival frames (UO-147): a decorative frame drawn over the office, one
// transparent image per canvas shape, light and optionally dark. The
// platform's frames are a catalogue here, like the plan table: their images
// are static files the web app ships, so nothing about them is stored but
// each org's choices. An org may add frames of its own, uploaded.
//
// Only one frame shows at a time. The org's own frame wins; among platform
// frames, the one the org most recently turned on; with the one switch off,
// none. Every date is in the org's time zone.

// platformFrame is one frame of the catalogue. Start and End are its default
// yearly window as MM-DD, both included; empty when it has none, and then it
// shows only when an org gives it dates.
type platformFrame struct {
	Key, Name, Icon string
	Start, End      string
}

// platformFrames is the catalogue, in the order the admin page lists it. The
// order also breaks a tie between two default frames that overlap.
var platformFrames = []platformFrame{
	{Key: "christmas", Name: "Christmas", Icon: "tree", Start: "12-20", End: "12-26"},
	{Key: "new_year", Name: "New Year", Icon: "fireworks", Start: "12-31", End: "01-02"},
	{Key: "diwali", Name: "Diwali", Icon: "lamp", Start: "10-20", End: "10-24"},
	{Key: "holi", Name: "Holi", Icon: "palette", Start: "03-13", End: "03-15"},
	{Key: "eid", Name: "Eid", Icon: "moon", Start: "03-30", End: "04-01"},
	{Key: "easter", Name: "Easter", Icon: "egg", Start: "04-03", End: "04-06"},
	{Key: "halloween", Name: "Halloween", Icon: "pumpkin", Start: "10-29", End: "10-31"},
	{Key: "celebration", Name: "Celebration", Icon: "confetti"},
}

func platformFrameByKey(key string) (platformFrame, bool) {
	for _, f := range platformFrames {
		if f.Key == key {
			return f, true
		}
	}
	return platformFrame{}, false
}

// frameShapes are the template canvas shapes, as the office service names
// them: every frame has an image for each.
var frameShapes = []string{"landscape", "square", "portrait"}

// platformImagePath is where the web app serves a platform frame's image:
// a relative path, never a host.
func platformImagePath(key, shape, variant string) string {
	return fmt.Sprintf("/frames/%s-%s-%s.svg", key, shape, variant)
}

func platformImages(key string) api.FrameImages {
	image := func(shape string) api.FrameImage {
		dark := platformImagePath(key, shape, "dark")
		return api.FrameImage{Light: platformImagePath(key, shape, "light"), Dark: &dark}
	}
	return api.FrameImages{Landscape: image("landscape"), Square: image("square"), Portrait: image("portrait")}
}

var monthDayShape = regexp.MustCompile(`^\d\d-\d\d$`)

// validMonthDay is whether s is a real MM-DD. 02-29 is one: in a year
// without it, a window across it still works, and one starting on it starts
// on 1 March.
func validMonthDay(s string) bool {
	if !monthDayShape.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", "2000-"+s)
	return err == nil
}

// parseDay is a calendar date, YYYY-MM-DD, as midnight UTC: a date, not an instant.
func parseDay(s string) (time.Time, bool) {
	d, err := time.Parse("2006-01-02", s)
	return d, err == nil
}

// dayIn is the calendar date at instant t in zone.
func dayIn(t time.Time, zone *time.Location) time.Time {
	local := t.In(zone)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
}

// inWindow is whether day falls in the yearly window start..end, both
// included; a start after the end wraps the year.
func inWindow(day time.Time, start, end string) bool {
	md := day.Format("01-02")
	if start <= end {
		return start <= md && md <= end
	}
	return md >= start || md <= end
}

// occurrence is the first and last day of the showing of start..end that
// day falls in.
func occurrence(day time.Time, start, end string) (time.Time, time.Time) {
	at := func(year int, md string) time.Time {
		d, _ := time.Parse("2006-01-02", fmt.Sprintf("%04d-%s", year, md))
		if d.IsZero() {
			// 02-29 in a year without it.
			d, _ = time.Parse("2006-01-02", fmt.Sprintf("%04d-03-01", year))
		}
		return d
	}
	y := day.Year()
	if start <= end {
		return at(y, start), at(y, end)
	}
	if day.Format("01-02") >= start {
		return at(y, start), at(y+1, end)
	}
	return at(y-1, start), at(y, end)
}

// frameState is a platform frame as it applies to one org: the catalogue's
// defaults with the org's choices over them.
type frameState struct {
	frame      platformFrame
	enabled    bool
	start, end string
	customized bool
	enabledAt  time.Time
}

// stateOf is frame f for an org whose choice about it is row, or nil when it
// has made none: then it is on with its default dates, if it has any.
func stateOf(f platformFrame, row *store.OrgFrameSetting) frameState {
	st := frameState{frame: f, enabled: f.Start != "", start: f.Start, end: f.End}
	if row == nil {
		return st
	}
	st.enabled = row.Enabled
	if row.StartMd.Valid && row.EndMd.Valid {
		st.start, st.end, st.customized = row.StartMd.String, row.EndMd.String, true
	}
	if row.EnabledAt.Valid {
		st.enabledAt = row.EnabledAt.Time
	}
	// A frame with no dates never shows, whatever the row says.
	st.enabled = st.enabled && st.start != ""
	return st
}

// statesOf is every platform frame for an org with the given rows.
func statesOf(rows []store.OrgFrameSetting) []frameState {
	byKey := map[string]*store.OrgFrameSetting{}
	for i := range rows {
		byKey[rows[i].FrameKey] = &rows[i]
	}
	out := make([]frameState, 0, len(platformFrames))
	for _, f := range platformFrames {
		out = append(out, stateOf(f, byKey[f.Key]))
	}
	return out
}

// showingPlatform is the platform frame showing on day, if any: of those on
// and in their window, the one most recently turned on, the catalogue's
// order breaking a tie.
func showingPlatform(day time.Time, states []frameState) (frameState, bool) {
	var best frameState
	found := false
	for _, st := range states {
		if !st.enabled || !inWindow(day, st.start, st.end) {
			continue
		}
		if !found || st.enabledAt.After(best.enabledAt) {
			best, found = st, true
		}
	}
	return best, found
}

func toPlatformFrame(st frameState) api.PlatformFrame {
	out := api.PlatformFrame{
		Key: api.PlatformFrameKey(st.frame.Key), Name: st.frame.Name, Icon: st.frame.Icon,
		Enabled: st.enabled, Customized: st.customized, Images: platformImages(st.frame.Key),
	}
	if st.frame.Start != "" {
		out.DefaultStartMd, out.DefaultEndMd = &st.frame.Start, &st.frame.End
	}
	if st.start != "" {
		start, end := st.start, st.end
		out.StartMd, out.EndMd = &start, &end
	}
	if !st.enabledAt.IsZero() {
		at := st.enabledAt
		out.EnabledAt = &at
	}
	return out
}
