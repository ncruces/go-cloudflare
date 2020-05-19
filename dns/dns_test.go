package dns

import (
	"context"
	"testing"
)

func TestResolveTLS(t *testing.T) {
	resolver := NewTLSResolver()
	ips, err := resolver.LookupIPAddr(context.TODO(), "one.one.one.one")
	if err != nil {
		t.Error(err)
	} else {
		t.Log(ips)
	}
}
