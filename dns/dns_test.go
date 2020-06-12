package dns

import (
	"net"
	"testing"
)

func TestDNS(t *testing.T) {
	if ips, err := net.LookupIP("one.one.one.one"); err != nil {
		t.Error(err)
	} else {
		t.Log(ips)
	}
}
