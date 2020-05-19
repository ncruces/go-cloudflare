// Package dns provides pure Go net.Resolvers backed by Cloudflare's 1.1.1.1.
package dns

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// NewTLSResolver returns a DNS over TLS net.Resolver.
//
// See:
//   https://developers.cloudflare.com/1.1.1.1/dns-over-tls/
func NewTLSResolver() *net.Resolver {
	index := 0
	addrs := [4]string{
		"1.1.1.1:853", "[2606:4700:4700::1111]:853",
		"1.0.0.1:853", "[2606:4700:4700::1001]:853",
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         "cloudflare-dns.com",
		ClientSessionCache: tls.NewLRUClientSessionCache(len(addrs)),
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, err error) {
			var d net.Dialer
			for i := 0; i < len(addrs); i++ {
				conn, err = d.DialContext(ctx, "tcp", addrs[index])
				if err != nil {
					index = (index + 1) % len(addrs)
					continue
				}
				conn.(*net.TCPConn).SetKeepAlive(true)
				conn.(*net.TCPConn).SetKeepAlivePeriod(5 * time.Minute)
				return tls.Client(conn, cfg), nil
			}
			return
		},
	}
}
