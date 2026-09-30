package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2001:4860:4860::8888": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "::1": false, "fe80::1": false, "fd00::1": false,
		"::ffff:127.0.0.1": false, "0.0.0.0": false,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

// Deployed, the client refuses to connect to a private address, whatever
// the URL an admin typed resolves to.
func TestHTTPClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := HTTPClient(false).Get(srv.URL); err == nil {
		t.Error("reached a loopback address")
	}
	if resp, err := HTTPClient(true).Get(srv.URL); err != nil {
		t.Errorf("local: %v", err)
	} else {
		resp.Body.Close()
	}
	c, err := New(context.Background(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.CheckURL("http://idp.example.com") == nil || c.CheckURL("https://user:pw@idp.example.com") == nil || c.CheckURL("https://idp.example.com/tenant") != nil {
		t.Error("CheckURL")
	}
}

func TestIssuerMatches(t *testing.T) {
	if !issuerMatches("https://a.test/x", "https://a.test/x", false) || issuerMatches("https://a.test/x", "https://a.test/y", false) {
		t.Error("strict")
	}
	if !issuerMatches("https://login.test/contoso.com/v2.0", "https://login.test/1234/v2.0", true) || issuerMatches("https://login.test/x", "https://evil.test/x", true) {
		t.Error("loose")
	}
}

func TestErrorCodeIsSafeToLog(t *testing.T) {
	if got := ErrorCode("invalid_grant\nsecret=abc def"); got != "invalid_grantsecretabcdef" {
		t.Errorf("%q", got)
	}
}
