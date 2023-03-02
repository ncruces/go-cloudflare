// Package acmecf solves DNS-01 challenges for acmez using Cloudflare.
package acmecf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
)

type dns01Solver struct {
	api    *cloudflare.API
	zone   string
	record string
}

// NewDNS01Solver creates an acmez.Solver that solves DNS-01 challenges
// using Cloudflare's Authoritative DNS, given the zone ID and a token
// with Zone.DNS permission.
func NewDNS01Solver(zone, token string) (acmez.Solver, error) {
	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		return nil, err
	}
	return NewDNS01SolverWithClient(api, zone), err
}

// NewDNS01SolverWithClient creates an acmez.Solver that solves DNS-01 challenges
// using Cloudflare's Authoritative DNS, given an API instance and zone ID.
func NewDNS01SolverWithClient(api *cloudflare.API, zone string) acmez.Solver {
	return &dns01Solver{
		api:  api,
		zone: zone,
	}
}

func (s *dns01Solver) Present(ctx context.Context, chal acme.Challenge) error {
	if chal.Type != acme.ChallengeTypeDNS01 {
		return errors.New("unexpected challenge")
	}

	rec := cloudflare.CreateDNSRecordParams{
		Type:    "TXT",
		Name:    chal.DNS01TXTRecordName(),
		Content: chal.DNS01KeyAuthorization(),
	}

	zone := cloudflare.ZoneIdentifier(s.zone)
	res, err := s.api.CreateDNSRecord(ctx, zone, rec)
	if err != nil {
		res, _, _ := s.api.ListDNSRecords(ctx, zone, cloudflare.ListDNSRecordsParams{
			Type:    "TXT",
			Name:    chal.DNS01TXTRecordName(),
			Content: chal.DNS01KeyAuthorization(),
		})
		if len(res) == 1 {
			s.record = res[0].ID
			return nil
		}
		return err
	}

	s.record = res.Result.ID
	return nil
}

func (s *dns01Solver) Wait(ctx context.Context, challenge acme.Challenge) error {
	if s.record == "" {
		return nil
	}

	var backoff = time.Second
	for start := time.Now(); time.Since(start) < 5*time.Minute; backoff *= 2 {
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}

		recs, err := lookupTXT(ctx, challenge.DNS01TXTRecordName())
		if err != nil {
			continue
		}

		for _, rec := range recs {
			if rec == challenge.DNS01KeyAuthorization() {
				return nil
			}
		}
	}
	return errors.New("timeout")
}

func (s *dns01Solver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	if s.record == "" {
		return nil
	}
	zone := cloudflare.ZoneIdentifier(s.zone)
	return s.api.DeleteDNSRecord(ctx, zone, s.record)
}

func lookupTXT(ctx context.Context, domain string) ([]string, error) {
	url := "https://dns.google/resolve?type=TXT&name=" + url.QueryEscape(domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	var dns struct {
		Answer []struct {
			Data string
		}
	}
	err = json.NewDecoder(res.Body).Decode(&dns)
	if err != nil {
		return nil, err
	}

	var ret []string
	for _, answer := range dns.Answer {
		if len := len(answer.Data); len > 2 {
			ret = append(ret, answer.Data[1:len-1])
		}
	}
	if len(ret) == 0 {
		return nil, errors.New(http.StatusText(http.StatusNotFound))
	}
	return ret, nil
}
