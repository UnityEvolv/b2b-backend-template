// Package timezone validates the IANA zone names the platform stores. Two
// zones exist everywhere: the org's and the person's. Both are names such as
// Europe/London, never an offset, so daylight saving is handled by the zone
// database rather than by anyone's arithmetic.
//
// The zone database is compiled in, so a service in a distroless image
// resolves names without /usr/share/zoneinfo.
package timezone

import (
	"errors"
	"strings"
	"time"
	_ "time/tzdata" // the zone database, for images without one
)

// ErrNotAZone means the value is not an IANA zone name.
var ErrNotAZone = errors.New("timezone: not an IANA zone name")

// Validate accepts an IANA zone name such as Asia/Kolkata or UTC and refuses
// everything else: offsets, abbreviations, "Local", and anything the zone
// database does not know.
func Validate(name string) error {
	if name == "" || name == "Local" || strings.HasPrefix(name, "Etc/") || len(name) > 64 {
		return ErrNotAZone
	}
	if name != "UTC" && !strings.Contains(name, "/") {
		// Abbreviations (IST, EST) are ambiguous; offsets (+05:30) drift.
		return ErrNotAZone
	}
	if _, err := time.LoadLocation(name); err != nil {
		return ErrNotAZone
	}
	return nil
}
