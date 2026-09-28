package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name   string
		hops   int
		remote string
		xff    []string
		want   string
	}{
		{"no proxy: the connection", 0, "203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"load balancer: the entry it appended for the client", 2, "10.0.0.5:4000", []string{"198.51.100.7, 35.1.2.3"}, "198.51.100.7"},
		{"a client writing its own entries cannot choose", 2, "10.0.0.5:4000", []string{"1.2.3.4, 5.6.7.8, 198.51.100.7, 35.1.2.3"}, "198.51.100.7"},
		{"entries across several headers", 2, "10.0.0.5:4000", []string{"9.9.9.9", "198.51.100.7, 35.1.2.3"}, "198.51.100.7"},
		{"shorter than the proxies could make: the connection", 2, "10.0.0.5:4000", []string{"198.51.100.7"}, "10.0.0.5"},
		{"not an address: the connection", 2, "10.0.0.5:4000", []string{"nonsense, 35.1.2.3"}, "10.0.0.5"},
		{"IPv6", 2, "10.0.0.5:4000", []string{"2001:db8::1, 35.1.2.3"}, "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIPWith(r, c.hops); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
