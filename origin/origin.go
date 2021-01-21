// Package origin configures an http.Server to only accept legitimate requests from Cloudflare.
//
// The server will only accept TLS 1.3 SNI requests matching one of the provided certificates,
// and it can authenticate origin pulls using mTLS.
//
// When the above checks fail, the TLS handshake fails without leaking server certificates.
//
// A net.Listener that only accepts connections from Cloudflare IP ranges can also be used.
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
//		ln, err := origin.Listen("tcp", ":https")
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

type stringError string

func (e stringError) Error() string { return string(e) }
