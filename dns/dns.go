// Package dns replaces the net.DefaultResolver with Cloudflare's 1.1.1.1.
//
// This is a caching DNS over HTTPS implementation using:
// https://github.com/ncruces/go-dns
//
// Usage:
//	import _ "github.com/ncruces/go-cloudflare/dns"
package dns

import (
	"net"

	"github.com/ncruces/go-dns"
)

func init() {
	net.DefaultResolver, _ = dns.NewDoHResolver(
		"https://cloudflare-dns.com/dns-query",
		dns.DoHAddresses(
			"2606:4700:4700::1111", "1.1.1.1",
			"2606:4700:4700::1001", "1.0.0.1"),
		dns.DoHCache())
}
