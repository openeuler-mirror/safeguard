package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateDNSCache_StoresEntry(t *testing.T) {
	initDNSCache()
	answer := &DNSAnswer{Domain: "example.com", Addresses: []net.IP{net.ParseIP("1.2.3.4")}, TTL: 300}
	updateDNSCache("example.com", answer)
	assert.Equal(t, "example.com", dnsCache["1.2.3.4"])
}

