package egress_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
)

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2001:4860:4860::8888": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "::1": false, "fe80::1": false, "fd00::1": false,
		"::ffff:127.0.0.1": false, "0.0.0.0": false,
	} {
		if got := egress.Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

func TestClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := egress.Client(egress.Options{}).Get(srv.URL); err == nil || !errors.Is(err, egress.ErrNotPublic) {
		t.Errorf("reached a loopback address: %v", err)
	}
	resp, err := egress.Client(egress.Options{Local: true}).Get(srv.URL)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	resp.Body.Close()
}

func TestNoRedirectsIsTheAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	resp, err := egress.Client(egress.Options{Local: true, Redirects: -1}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status %d, want the redirect itself", resp.StatusCode)
	}
}

type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestCheckHost(t *testing.T) {
	r := resolver{
		"hooks.example.com":    {netip.MustParseAddr("93.184.216.34")},
		"internal.example.com": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.5")},
	}
	for host, ok := range map[string]bool{
		"hooks.example.com": true, "8.8.8.8": true, "unknown.example.com": true,
		"internal.example.com": false, "10.0.0.1": false, "127.0.0.1": false, "::1": false,
		"169.254.169.254": false, "localhost": false, "": false,
	} {
		err := egress.CheckHost(context.Background(), r, host)
		if (err == nil) != ok {
			t.Errorf("%q: %v", host, err)
		}
	}
}
