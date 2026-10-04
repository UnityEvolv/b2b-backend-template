package oidc

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
)

// HTTPClient is the client the service talks to providers with. An admin
// names the issuer, so the service fetches a URL someone else chose:
// deployed, it connects only to public addresses, checked at connect time
// after resolution (so neither a redirect nor a DNS answer reaches the
// metadata server or a private service). local allows every address, for
// the stub issuer on a laptop and tests. The dialer is pkg/egress's, which
// the webhooks service delivers through too.
func HTTPClient(local bool) *http.Client {
	return egress.Client(egress.Options{Local: local, Timeout: 10 * time.Second, Redirects: 2})
}

// Public is whether ip is a public unicast address.
func Public(ip netip.Addr) bool { return egress.Public(ip) }

// HTTP is the client the service fetches what an admin names with: the
// provider's documents, and a SAML provider's metadata.
func (c *Client) HTTP() *http.Client { return c.http }
