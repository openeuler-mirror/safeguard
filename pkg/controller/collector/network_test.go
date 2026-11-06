package collector

import (
	"errors"
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

func TestRemoteAddressToCIDR(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "proc net tcp ipv4 address",
			raw:      "0100007F:0035",
			expected: "127.0.0.1/32",
		},
		{
			name:     "proc net tcp6 ipv6 address",
			raw:      "00000000000000000000000001000000:01BB",
			expected: "::1/128",
		},
		{
			name:     "proc net tcp6 multiple words",
			raw:      "B80D0120000000000000000001000000:01BB",
			expected: "2001:db8::1/128",
		},
		{
			name:     "proc net tcp6 ipv4 mapped",
			raw:      "0000000000000000FFFF0000010200C0:01BB",
			expected: "192.0.2.1/32",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := remoteAddressToCIDR(test.raw)
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestRemoteAddressToCIDR_RejectsInvalidAddresses(t *testing.T) {
	tests := []string{
		"invalid",
		"not-hex:0035",
		"00000000:0000",
		"00000000000000000000000000000000:0000",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := remoteAddressToCIDR(raw)
			require.Error(t, err)
		})
	}
}

func TestInterfaceAddressToCIDR(t *testing.T) {
	ipNet := &net.IPNet{IP: net.ParseIP("10.0.0.8"), Mask: net.CIDRMask(24, 32)}
	cidr, ok := interfaceAddressToCIDR(ipNet)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.8/32", cidr)

	ipAddr := &net.IPAddr{IP: net.ParseIP("2001:db8::8")}
	cidr, ok = interfaceAddressToCIDR(ipAddr)
	require.True(t, ok)
	assert.Equal(t, "2001:db8::8/128", cidr)
}

func TestInterfaceAddressErrors(t *testing.T) {
	injected := errors.New("interface disappeared")
	interfaces := []net.Interface{{Name: "eth0"}, {Name: "eth1"}}
	calls := 0
	addrs, err := interfaceCIDRs(interfaces, func(iface net.Interface) ([]net.Addr, error) {
		calls++
		if iface.Name == "eth1" {
			return nil, injected
		}
		return []net.Addr{&net.IPAddr{IP: net.ParseIP("192.0.2.1")}}, nil
	})
	require.ErrorIs(t, err, injected)
	require.ErrorContains(t, err, "eth1")
	require.Empty(t, addrs)
	require.Equal(t, 2, calls)
}
