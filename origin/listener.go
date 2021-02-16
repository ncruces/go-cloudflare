package origin

import (
	"bufio"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const errNotCloudflare stringError = "not a Cloudflare IP"

var (
	ips     atomic.Value
	mutex   sync.Mutex
	refresh time.Time
)

// Listen only accepts TCP connections from Cloudflare IP ranges.
func Listen(network, address string) (net.Listener, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: &net.AddrError{Err: "unexpected address type", Addr: address}}
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	go updateIPs()
	return listener{ln}, nil
}

// NewListener returns a listener that only accepts TCP connections from Cloudflare IP ranges.
func NewListener(ln net.Listener) net.Listener {
	return listener{ln}
}

var _ net.Listener = listener{}
var _ net.Conn = conn{}

type listener struct {
	net.Listener
}

func (ln listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !checkIP(c.RemoteAddr()) {
		c.Close()
		return conn{c}, nil
	}
	return c, nil
}

type conn struct {
	net.Conn
}

func (c conn) Read(b []byte) (n int, err error)   { return 0, errNotCloudflare }
func (c conn) Write(b []byte) (n int, err error)  { return 0, errNotCloudflare }
func (c conn) SetDeadline(t time.Time) error      { return errNotCloudflare }
func (c conn) SetReadDeadline(t time.Time) error  { return errNotCloudflare }
func (c conn) SetWriteDeadline(t time.Time) error { return errNotCloudflare }
func (c conn) Close() error                       { return nil }

func checkIP(addr net.Addr) bool {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
	}

	ips, _ := ips.Load().([]net.IPNet)
	for _, ipnet := range ips {
		if ipnet.Contains(ip) {
			return true
		}
	}
	// update on failure: maybe it's a new IP?
	for _, ipnet := range updateIPs() {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

func updateIPs() []net.IPNet {
	// shared state
	mutex.Lock()
	defer mutex.Unlock()

	// update at most once an hour, even if it fails
	if time.Since(refresh) > time.Hour {
		refresh = time.Now()

		ipv4, err := loadIPs("https://www.cloudflare.com/ips-v4")
		if err != nil {
			if ips.Load() == nil {
				// fatal because it's our first time doing this
				log.Fatalln("failed to fecth Cloudflare IPv4s:", err)
			}
			log.Println("failed to update Cloudflare IPv4s:", err)
			return nil
		}
		ipv6, err := loadIPs("https://www.cloudflare.com/ips-v6")
		if err != nil {
			if ips.Load() == nil {
				// fatal because it's our first time doing this
				log.Fatalln("failed to fecth Cloudflare IPv6s:", err)
			}
			log.Println("failed to update Cloudflare IPv6s:", err)
			return nil
		}

		ip := append(ipv4, ipv6...)
		ips.Store(ip)
		return ip
	}

	// another routine might've updated it
	return ips.Load().([]net.IPNet)
}

func loadIPs(url string) ([]net.IPNet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(res.Status)
	}

	var ips []net.IPNet
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		_, n, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return nil, err
		}
		ips = append(ips, *n)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, err
}
