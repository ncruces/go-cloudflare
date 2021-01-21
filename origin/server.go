package origin

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	errMissingServerName    stringError = "missing server name"
	errMismatchedServerName stringError = "mismatched server name"
)

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

// MatchServerNameHost checks if SNI matches the Host header for a TLS http.Request.
func MatchHostServerName(r *http.Request) bool {
	if r.TLS == nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	return r.TLS.ServerName == host
}

func serveMux(w http.ResponseWriter, r *http.Request) {
	if MatchHostServerName(r) {
		http.DefaultServeMux.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}
