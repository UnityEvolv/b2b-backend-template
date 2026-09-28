package httpx

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// trustedHops is how many entries at the end of X-Forwarded-For our own
// proxies appended. Google's external Application Load Balancer appends two,
// "<client>, <load balancer>", so deployed it is 2 (TRUSTED_PROXY_HOPS); on a
// laptop there is no proxy and it is 0.
var trustedHops = hopsFromEnv()

func hopsFromEnv() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TRUSTED_PROXY_HOPS")))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// ClientIP is the address a request came from. With no trusted proxy it is
// the connection's address. Behind the platform's proxies it is the entry
// the outermost trusted proxy appended to X-Forwarded-For: counted from the
// right, so whatever a client writes into the header itself is never used.
// A header shorter than the trusted proxies could have made falls back to
// the connection's address.
func ClientIP(r *http.Request) string {
	return clientIPWith(r, trustedHops)
}

func clientIPWith(r *http.Request, hops int) string {
	if hops > 0 {
		var entries []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			for _, part := range strings.Split(h, ",") {
				entries = append(entries, strings.TrimSpace(part))
			}
		}
		if len(entries) >= hops {
			if ip := net.ParseIP(entries[len(entries)-hops]); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
