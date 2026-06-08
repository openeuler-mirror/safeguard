package collector

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPAddressToCIDR(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		{
			name:     "ipv4 host address",
			ip:       net.ParseIP("192.168.0.10"),
			expected: "192.168.0.10/32",
		},
		{
			name:     "ipv6 host address",
			ip:       net.ParseIP("2001:db8::10"),
			expected: "2001:db8::10/128",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, ok := ipAddressToCIDR(test.ip)
			require.True(t, ok)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestIPAddressToCIDR_SkipsUnspecifiedAddresses(t *testing.T) {
	_, ok := ipAddressToCIDR(net.IPv4zero)
	assert.False(t, ok)

	_, ok = ipAddressToCIDR(net.IPv6zero)
	assert.False(t, ok)
}
