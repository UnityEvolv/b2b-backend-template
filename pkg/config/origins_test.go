package config_test

import (
	"reflect"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
)

func TestEveryHostDerivesFromTheBase(t *testing.T) {
	h := config.HostsFor(" UnityOfis.UnityEvolv.com ")
	want := config.Hosts{
		Base:     "unityofis.unityevolv.com",
		Ofis:     "unityofis.unityevolv.com",
		Admin:    "admin.unityofis.unityevolv.com",
		Platform: "platform.unityofis.unityevolv.com",
		API:      "api.unityofis.unityevolv.com",
		Realtime: "rt.unityofis.unityevolv.com",
		TURN:     "turn.unityofis.unityevolv.com",
	}
	if h != want {
		t.Fatalf("got %+v\nwant %+v", h, want)
	}
}

func TestAppOrigins(t *testing.T) {
	got := config.AppOrigins("unityofis.unityevolv.com", []string{" unityofis://app/ ", ""})
	want := []string{
		"https://unityofis.unityevolv.com",
		"https://admin.unityofis.unityevolv.com",
		"https://platform.unityofis.unityevolv.com",
		"unityofis://app",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// A laptop has no base hostname, only the dev servers it names.
	local := config.AppOrigins("", []string{"http://localhost:5173"})
	if !reflect.DeepEqual(local, []string{"http://localhost:5173"}) {
		t.Fatalf("local: %v", local)
	}
}
