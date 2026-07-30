package collector

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPAddressToCIDR_IPv4Loopback(t *testing.T) {
	cidr, ok := ipAddressToCIDR(net.ParseIP("127.0.0.1"))
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1/32", cidr)
}

func TestIPAddressToCIDR_IPv6Loopback(t *testing.T) {
	cidr, ok := ipAddressToCIDR(net.ParseIP("::1"))
	require.True(t, ok)
	assert.Equal(t, "::1/128", cidr)
}

func TestIPAddressToCIDR_NilIPReturnsFalse(t *testing.T) {
	_, ok := ipAddressToCIDR(nil)
	assert.False(t, ok)
}
