package notify

import (
	"slices"
	"time"
)

// Quiet is a person's quiet hours: a daily window on some weekdays, in their
// own time zone. During it push and email are held; the feed still lands.
type Quiet struct {
	Enabled bool
	// Minutes after midnight. End before start is a window across midnight.
	Start, End int
	// ISO weekdays, 1 Monday to 7 Sunday: the day the window starts on.
	Days []int16
	Zone *time.Location
}

func minuteOf(t time.Time) int { return t.Hour()*60 + t.Minute() }

func isoDay(t time.Time) int16 {
	d := int16(t.Weekday())
	if d == 0 {
		return 7
	}
	return d
}

// Until reports whether now is inside quiet hours and, if so, when they end.
func (q Quiet) Until(now time.Time) (time.Time, bool) {
	if !q.Enabled || q.Start == q.End {
		return time.Time{}, false
	}
	zone := q.Zone
	if zone == nil {
		zone = time.UTC
	}
	local := now.In(zone)
	m := minuteOf(local)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, zone)
	at := func(day time.Time, minute int) time.Time {
		return time.Date(day.Year(), day.Month(), day.Day(), minute/60, minute%60, 0, 0, zone)
	}
	if q.Start < q.End {
		// Within one day.
		if m >= q.Start && m < q.End && slices.Contains(q.Days, isoDay(local)) {
			return at(midnight, q.End), true
		}
		return time.Time{}, false
	}
	// Across midnight: the evening part belongs to today, the morning part
	// to the window that started yesterday.
	if m >= q.Start && slices.Contains(q.Days, isoDay(local)) {
		return at(midnight.AddDate(0, 0, 1), q.End), true
	}
	yesterday := midnight.AddDate(0, 0, -1)
	if m < q.End && slices.Contains(q.Days, isoDay(yesterday)) {
		return at(midnight, q.End), true
	}
	return time.Time{}, false
}

// DigestDue reports whether a person's digest is due at now: their chosen
// minute (or the start of their working day) has passed today, in their
// zone, and the last digest was before it.
func DigestDue(now time.Time, zone *time.Location, minute int, last time.Time) bool {
	if zone == nil {
		zone = time.UTC
	}
	local := now.In(zone)
	due := time.Date(local.Year(), local.Month(), local.Day(), minute/60, minute%60, 0, 0, zone)
	return !local.Before(due) && last.Before(due)
}
