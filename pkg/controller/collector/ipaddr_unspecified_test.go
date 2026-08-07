package collector

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPAddressToCIDR_UnspecifiedIPv4(t *testing.T) {
	cidr, ok := ipAddressToCIDR(net.IPv4zero)
	assert.False(t, ok)
	assert.Empty(t, cidr)
}

func TestIPAddressToCIDR_UnspecifiedIPv6(t *testing.T) {
	cidr, ok := ipAddressToCIDR(net.IPv6unspecified)
	assert.False(t, ok)
	assert.Empty(t, cidr)
}
