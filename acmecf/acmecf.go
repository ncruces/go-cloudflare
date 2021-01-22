// Package acmecf solves DNS-01 challenges for acmez using Cloudflare.
package acmecf

import (
	"context"
	"errors"
	"net"
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

	res, err := s.api.CreateDNSRecord(s.zone, cloudflare.DNSRecord{
		Type:    "TXT",
		Name:    chal.DNS01TXTRecordName(),
		Content: chal.DNS01KeyAuthorization(),
	})
	if err != nil {
		return err
	}

	s.record = res.Result.ID
	return nil
}

func (s *dns01Solver) Wait(ctx context.Context, challenge acme.Challenge) error {
	if s.record == "" {
		return nil
	}

	for start := time.Now(); time.Since(start) < time.Minute; {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}

		recs, err := net.LookupTXT(challenge.DNS01TXTRecordName())

		var derr *net.DNSError
		if errors.As(err, &derr) && (derr.IsNotFound || derr.IsTemporary || derr.IsTimeout) {
			continue
		}
		if err != nil {
			return err
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
	return s.api.DeleteDNSRecord(s.zone, s.record)
}
