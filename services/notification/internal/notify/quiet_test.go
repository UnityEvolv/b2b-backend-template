package notify

import (
	"testing"
	"time"
)

func TestQuietHours(t *testing.T) {
	kolkata, _ := time.LoadLocation("Asia/Kolkata")
	every := []int16{1, 2, 3, 4, 5, 6, 7}
	night := Quiet{Enabled: true, Start: 22 * 60, End: 7 * 60, Days: every, Zone: kolkata}

	// 23:00 in Kolkata on a Wednesday: quiet until 07:00 Thursday.
	at := time.Date(2026, 9, 23, 23, 0, 0, 0, kolkata)
	until, quiet := night.Until(at)
	if !quiet || !until.Equal(time.Date(2026, 9, 24, 7, 0, 0, 0, kolkata)) {
		t.Errorf("evening: %v %v", until, quiet)
	}
	// 06:00 the next morning: still the same window.
	if until, quiet := night.Until(time.Date(2026, 9, 24, 6, 0, 0, 0, kolkata)); !quiet || until.Hour() != 7 {
		t.Errorf("morning: %v %v", until, quiet)
	}
	// Noon: not quiet. The same instant in UTC is judged in the person's zone.
	if _, quiet := night.Until(time.Date(2026, 9, 24, 12, 0, 0, 0, kolkata).UTC()); quiet {
		t.Error("noon is not quiet")
	}
	// Weekdays only: a window that starts on Friday runs into Saturday
	// morning, and Saturday evening is not quiet.
	weekdays := Quiet{Enabled: true, Start: 22 * 60, End: 7 * 60, Days: []int16{1, 2, 3, 4, 5}, Zone: kolkata}
	if _, quiet := weekdays.Until(time.Date(2026, 9, 26, 6, 0, 0, 0, kolkata)); !quiet {
		t.Error("Saturday morning after a Friday night")
	}
	if _, quiet := weekdays.Until(time.Date(2026, 9, 26, 23, 0, 0, 0, kolkata)); quiet {
		t.Error("Saturday night is not a weekday")
	}
	if _, quiet := (Quiet{Enabled: false, Start: 0, End: 1439, Days: every}).Until(at); quiet {
		t.Error("off is off")
	}
}

func TestDigestDue(t *testing.T) {
	london, _ := time.LoadLocation("Europe/London")
	now := time.Date(2026, 9, 24, 9, 5, 0, 0, london)
	if !DigestDue(now, london, 9*60, time.Date(2026, 9, 23, 9, 0, 0, 0, london)) {
		t.Error("due after nine with yesterday's sent")
	}
	if DigestDue(now, london, 9*60, time.Date(2026, 9, 24, 9, 1, 0, 0, london)) {
		t.Error("already sent today")
	}
	if DigestDue(now, london, 10*60, time.Time{}) {
		t.Error("not yet ten")
	}
}

func TestResolve(t *testing.T) {
	got := Resolve([]byte(`{"room_message":{"in_app":true,"push":true,"email":false},"knock":{"in_app":true,"push":false,"email":true}}`), []byte(`{"mention":{"in_app":true,"push":false,"email":false}}`))
	if !got[RoomMessage].Push {
		t.Error("the person's choice")
	}
	if got[Mention].Push {
		t.Error("the org's default where the person chose nothing")
	}
	if got[Knock].InApp || got[Knock].Email || got[Knock].Push {
		t.Error("knocks are push only, whatever is stored")
	}
	if !got[AdminBilling].Email {
		t.Error("the platform's default")
	}
}
