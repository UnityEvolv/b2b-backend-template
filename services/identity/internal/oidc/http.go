package oidc

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// HTTPClient is the client the service talks to providers with. An admin
// names the issuer, so the service fetches a URL someone else chose:
// deployed, it connects only to public addresses, checked at connect time
// after resolution (so neither a redirect nor a DNS answer reaches the
// metadata server or a private service). local allows every address, for
// the stub issuer on a laptop and tests.
func HTTPClient(local bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !local {
		dialer.Control = publicOnly
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// errNotPublic refuses a connection to an address that is not on the
// public internet.
var errNotPublic = errors.New("not a public address")

func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s", errNotPublic, host)
	}
	if !Public(ip) {
		return fmt.Errorf("%w: %s", errNotPublic, ip)
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
