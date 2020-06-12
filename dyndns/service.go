// Package dyndns dynamically updates A/AAAA DNS records on Cloudflare.
//
// Unlike other packages, this is intended to be used as a library (e.g. alongside an http.Server).
// It uses Cloudflare's 1.1.1.1 to get your public IP,
// and API Tokens for authentication.
//
// See:
//   https://blog.cloudflare.com/api-tokens-general-availability/
//
// Usage:
//	func main() {
//		go dyndns.SyncDNS("example.com", "[Zone ID]", "[Edit zone DNS Token]", time.Minute)
//
//		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
//			io.WriteString(w, "Hello, world!\n")
//		})
//		log.Fatal(http.ListenAndServe(":http", nil))
//	}
package dyndns

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

// UpdateDNS updates A/AAAA DNS records to your current public IP.
func UpdateDNS(domain, zone, token string) error {
	up, err := newUpdater(domain, zone, token)
	if err != nil {
		return err
	}
	return up.updateRecords()
}

// SyncDNS enters a loop keeping A/AAAA DNS records up to date with your current public IP.
func SyncDNS(domain, zone, token string, polling time.Duration) error {
	up, err := newUpdater(domain, zone, token)
	if err != nil {
		return err
	}
	for {
		if err := up.updateRecords(); err != nil {
			log.Println("failed to update DNS records:", err)
		}
		time.Sleep(polling)
	}
}

var defaultClient = &http.Client{Timeout: 5 * time.Second}

type updater struct {
	api        *cloudflare.API
	zone       string
	a, aaaa    string
	ipv4, ipv6 string
}

func newUpdater(domain, zone, token string) (*updater, error) {
	api, err := cloudflare.NewWithAPIToken(token, cloudflare.HTTPClient(defaultClient))
	if err != nil {
		return nil, err
	}

	up := updater{api: api, zone: zone}

	if err := up.loadRecords(domain); err != nil {
		return nil, err
	}

	return &up, nil
}

func (up *updater) loadRecords(domain string) error {
	recs, err := up.api.DNSRecords(up.zone, cloudflare.DNSRecord{Name: domain})
	if err != nil {
		return err
	}

	for i := range recs {
		switch recs[i].Type {
		case "A":
			if up.a != "" {
				return errors.New("Multiple A records found for " + domain)
			}
			up.a = recs[i].ID
			up.ipv4 = recs[i].Content
		case "AAAA":
			if up.aaaa != "" {
				return errors.New("Multiple AAAA records found for " + domain)
			}
			up.aaaa = recs[i].ID
			up.ipv6 = recs[i].Content
		}
	}
	if up.a == "" && up.aaaa == "" {
		return errors.New("No A/AAAA records found for " + domain)
	}

	return nil
}

func (up *updater) updateRecords() (err error) {
	if up.a != "" {
		ip, e := PublicIPv4()
		if e == nil && ip != up.ipv4 {
			e = up.updateRecord(up.a, ip)
		}
		if e == nil {
			up.ipv4 = ip
		} else {
			err = e
		}
	}

	if up.aaaa != "" {
		ip, e := PublicIPv6()
		if e == nil && ip != up.ipv6 {
			e = up.updateRecord(up.aaaa, ip)
		}
		if e == nil {
			up.ipv6 = ip
		} else {
			err = e
		}
	}

	return
}

func (up *updater) updateRecord(record, content string) error {
	rec, err := up.api.DNSRecord(up.zone, record)
	if err == nil && rec.Content != content {
		rec.Content = content
		_, err = up.api.Raw("PATCH", "/zones/"+up.zone+"/dns_records/"+record, rec)
	}
	return err
}

// PublicIPv4 gets your public v4 IP.
func PublicIPv4() (string, error) {
	return publicIP("1.1.1.1", "1.0.0.1")
}

// PublicIPv6 gets your public v6 IP.
func PublicIPv6() (string, error) {
	return publicIP("[2606:4700:4700::1111]", "[2606:4700:4700::1001]")
}

func publicIP(primary, secondary string) (string, error) {
	ip, err := tryGetIP("https://" + primary + "/cdn-cgi/trace")
	if err != nil {
		return tryGetIP("https://" + secondary + "/cdn-cgi/trace")
	}
	return ip, err
}

func tryGetIP(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	res, err := defaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", errors.New(http.StatusText(res.StatusCode))
	}

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		const prefix = "ip="
		if bytes.HasPrefix(scanner.Bytes(), []byte(prefix)) {
			return string(scanner.Bytes()[len(prefix):]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("parse error: ip not found")
}
