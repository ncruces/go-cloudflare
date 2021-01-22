package origin

import (
	"net"
	"testing"
)

func Test_checkIP(t *testing.T) {
	if addr, err := net.ResolveTCPAddr("tcp4", "dns.google:853"); err != nil {
		t.Fatal(err)
	} else if checkIP(addr) {
		t.Errorf("not a Cloudflare IP: %v", addr)
	}

	if addr, err := net.ResolveTCPAddr("tcp6", "dns.google:853"); err != nil {
		t.Fatal(err)
	} else if checkIP(addr) {
		t.Errorf("not a Cloudflare IP: %v", addr)
	}
}
