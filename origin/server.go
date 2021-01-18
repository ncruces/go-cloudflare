// Package origin configures an http.Server to only accept legitimate requests from Cloudflare.
//
// The server will only accept TLS 1.3 SNI requests matching one of the provided certificates,
// and authenticates origin pulls using mTLS.
//
// A net.Listener that only accepts connections from Cloudflare IP ranges can also be used.
//
// If any of the above checks fail, TLS handshake fails without leaking server certificates.
//
// See:
//   https://www.cloudflare.com/ips/
//   https://origin-pull.cloudflare.com/
//
// Usage:
//	func main() {
// 		server, err := origin.NewServer("cert.pem", "key.pem", "origin-pull-ca.pem")
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		ln, err := origin.Listen(":https")
//		if err != nil {
//			log.Fatal(err)
//		}
//		defer ln.Close()
//
//		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
//			io.WriteString(w, "Hello, Cloudflare!\n")
//		})
//		log.Fatal(server.ServeTLS(ln, "", ""))
//	}
package origin

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type constError string

func (e constError) Error() string { return string(e) }

const (
	errNotCloudflare        constError = "not a Cloudflare IP"
	errMissingServerName    constError = "missing server name"
	errMismatchedServerName constError = "mismatched server name"
)

var (
	ips     atomic.Value
	mutex   sync.Mutex
	refresh time.Time
)

// Listen accepts TCP connections from Cloudflare IP ranges.
func Listen(address string) (net.Listener, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	go updateIPs()
	return listener{ln}, nil
}

type listener struct {
	net.Listener
}

func (ln listener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !checkIP(conn) {
		conn.Close()
		return nil, errNotCloudflare
	}
	return conn, nil
}

// NewServer creates a Cloudflare origin http.Server.
//
// Filenames containing a certificate and matching private key for the server must be provided.
// The filename to the origin pull CA certificate is optional.
func NewServer(certFile, keyFile, pullCAFile string) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	var pool *x509.CertPool

	if pullCAFile != "" {
		pull, err := ioutil.ReadFile(pullCAFile)
		if err != nil {
			return nil, err
		}

		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(pull)
	}

	return NewServerWithCerts(pool, cert), nil
}

// NewServerWithCerts creates a Cloudflare origin http.Server from loaded certificates.
//
// The origin pull CA certificate is optional.
// At least one server certificate must be provided.
func NewServerWithCerts(pullCA *x509.CertPool, cert ...tls.Certificate) *http.Server {
	// require TLS 1.3
	config := &tls.Config{MinVersion: tls.VersionTLS13}

	config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// require SNI
		if info.ServerName == "" {
			return nil, errMissingServerName
		}

		// find matching certificate
		for i := range cert {
			if err := info.SupportsCertificate(&cert[i]); err == nil {
				return &cert[i], nil
			}
		}

		return nil, errMismatchedServerName
	}

	// validate client certificate against origin pull certificate
	if pullCA != nil {
		config.ClientCAs = pullCA
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// default port, reasonably large default timeouts
	return &http.Server{
		TLSConfig:         config,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       1 * time.Minute,
		WriteTimeout:      1 * time.Minute,
		IdleTimeout:       10 * time.Minute,
		Handler:           http.HandlerFunc(serveMux),
	}
}

func serveMux(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if host == r.TLS.ServerName {
		http.DefaultServeMux.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

func checkIP(conn net.Conn) bool {
	var ip net.IP
	switch addr := conn.RemoteAddr().(type) {
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
