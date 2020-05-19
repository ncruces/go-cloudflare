package init

import (
	"net"

	"github.com/ncruces/go-cloudflare/dns"
)

func init() {
	net.DefaultResolver = dns.NewTLSResolver()
}
