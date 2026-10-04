// Package egress is the HTTP client for addresses someone else chose: an
// identity provider an admin names, a webhook endpoint a customer
// registers. Deployed, it connects only to public addresses, checked at
// connect time after name resolution, so neither a redirect nor a DNS
// answer reaches the metadata server or a private service. local allows
// every address, for a stub on a laptop and tests; each service refuses to
// start with it outside ENVIRONMENT=local.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrNotPublic refuses a connection to an address that is not on the
// public internet.
var ErrNotPublic = errors.New("not a public address")

// Options shape a Client.
type Options struct {
	// Local allows every address: a laptop or a test only.
	Local bool
	// Timeout is the whole request's, answer included. Zero is 10 seconds.
	Timeout time.Duration
	// Redirects is how many redirects are followed; each lands on a public
	// address too. Negative follows none: the redirect is the answer.
	Redirects int
}

// Client is an HTTP client under o: no proxy, a 5-second connect, and,
// unless Local, public addresses only.
func Client(o Options) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !o.Local {
		dialer.Control = publicOnly
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	redirects := o.Redirects
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if redirects < 0 {
				return http.ErrUseLastResponse
			}
			if len(via) > redirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotPublic, host)
	}
	if !Public(ip) {
		return fmt.Errorf("%w: %s", ErrNotPublic, ip)
	}
	return nil
}

// Public is whether ip is a public unicast address.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// Carrier-grade NAT, and the benchmarking and documentation ranges.
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b::/96"),
	} {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Resolver looks a host name up; net.DefaultResolver in a service.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// CheckHost refuses a host that is, or resolves to, an address that is not
// public: the early answer for an admin typing a URL, with a message they
// can act on. The connect-time check in Client is still what holds, since a
// DNS answer can change after this. A name that does not resolve now is
// not refused: it may before the first request is sent.
func CheckHost(ctx context.Context, r Resolver, host string) error {
	if host == "" || host == "localhost" {
		return fmt.Errorf("%w: %s", ErrNotPublic, host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !Public(ip) {
			return fmt.Errorf("%w: %s", ErrNotPublic, ip)
		}
		return nil
	}
	if r == nil {
		return nil
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if !Public(a) {
			return fmt.Errorf("%w: %s resolves to %s", ErrNotPublic, host, a)
		}
	}
	return nil
}
