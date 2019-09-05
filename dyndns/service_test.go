package dyndns

import (
	"testing"
)

func TestGetIPs(t *testing.T) {
	if ipv4, err := PublicIPv4(); err != nil {
		t.Error(err)
	} else {
		t.Log(ipv4)
	}

	if ipv6, err := PublicIPv6(); err != nil {
		t.Error(err)
	} else {
		t.Log(ipv6)
	}
}
