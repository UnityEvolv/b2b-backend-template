package server

import (
	"testing"
	"time"
)

func day(s string) time.Time {
	d, _ := parseDay(s)
	return d
}

func TestInWindowAndOccurrence(t *testing.T) {
	for _, c := range []struct {
		day, start, end string
		in              bool
		from, to        string
	}{
		{"2026-10-20", "10-20", "10-24", true, "2026-10-20", "2026-10-24"},
		{"2026-10-24", "10-20", "10-24", true, "2026-10-20", "2026-10-24"},
		{"2026-10-25", "10-20", "10-24", false, "", ""},
		{"2026-12-31", "12-31", "01-02", true, "2026-12-31", "2027-01-02"},
		{"2027-01-02", "12-31", "01-02", true, "2026-12-31", "2027-01-02"},
		{"2027-01-03", "12-31", "01-02", false, "", ""},
		{"2026-06-15", "06-15", "06-15", true, "2026-06-15", "2026-06-15"},
		// 29 February in a year without it: a window across it still works.
		{"2027-03-01", "02-28", "03-02", true, "2027-02-28", "2027-03-02"},
	} {
		d := day(c.day)
		if got := inWindow(d, c.start, c.end); got != c.in {
			t.Errorf("%s in %s..%s: %v", c.day, c.start, c.end, got)
			continue
		}
		if !c.in {
			continue
		}
		from, to := occurrence(d, c.start, c.end)
		if from.Format("2006-01-02") != c.from || to.Format("2006-01-02") != c.to {
			t.Errorf("%s in %s..%s: showing %s..%s", c.day, c.start, c.end, from.Format("2006-01-02"), to.Format("2006-01-02"))
		}
	}
}

func TestValidMonthDay(t *testing.T) {
	for s, want := range map[string]bool{"01-01": true, "02-29": true, "12-31": true, "02-30": false, "13-01": false, "1-01": false, "00-10": false, "": false, "10-20x": false} {
		if got := validMonthDay(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

func TestDayInZone(t *testing.T) {
	kolkata, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 7, 19, 0, 0, 0, time.UTC)
	if got := dayIn(at, kolkata).Format("2006-01-02"); got != "2026-11-08" {
		t.Errorf("in Kolkata: %s", got)
	}
	if got := dayIn(at, time.UTC).Format("2006-01-02"); got != "2026-11-07" {
		t.Errorf("in UTC: %s", got)
	}
}

func TestCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range platformFrames {
		if seen[f.Key] || f.Name == "" || !iconShape.MatchString(f.Icon) {
			t.Errorf("frame %+v", f)
		}
		seen[f.Key] = true
		if (f.Start == "") != (f.End == "") || (f.Start != "" && (!validMonthDay(f.Start) || !validMonthDay(f.End))) {
			t.Errorf("frame %s: dates %q..%q", f.Key, f.Start, f.End)
		}
	}
}
