package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainNameToBPFMapKey_IPv4(t *testing.T) {
	addrs, err := domainNameToBPFMapKey("example.com", []net.IP{net.ParseIP("10.0.0.1")})
	assert.NoError(t, err)
	assert.Len(t, addrs, 1)
	assert.NotNil(t, addrs[0].key)
}

func TestDomainNameToBPFMapKey_IPv6(t *testing.T) {
	addrs, err := domainNameToBPFMapKey("example.com", []net.IP{net.ParseIP("2001:db8::1")})
	assert.NoError(t, err)
	assert.Len(t, addrs, 1)
	assert.NotNil(t, addrs[0].key)
}

func TestDomainNameToBPFMapKey_EmptyAddresses(t *testing.T) {
	addrs, err := domainNameToBPFMapKey("example.com", []net.IP{})
	assert.NoError(t, err)
	assert.Empty(t, addrs)
}
