package timezone_test

import (
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/timezone"
)

func TestValidate(t *testing.T) {
	for _, ok := range []string{"UTC", "Asia/Kolkata", "Europe/London", "America/Argentina/Buenos_Aires"} {
		if err := timezone.Validate(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Local", "IST", "EST", "+05:30", "UTC+5", "Etc/GMT-5", "Asia/Nowhere", "asia/kolkata", "GMT"} {
		if err := timezone.Validate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
