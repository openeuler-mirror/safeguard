package network

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCidrToBPFMapKey_IPv4(t *testing.T) {
	ipaddr, err := cidrToBPFMapKey("10.0.0.0/24")
	assert.NoError(t, err)
	assert.NotNil(t, ipaddr.key)
}

func TestCidrToBPFMapKey_IPv6(t *testing.T) {
	ipaddr, err := cidrToBPFMapKey("2001:db8::/64")
	assert.NoError(t, err)
	assert.NotNil(t, ipaddr.key)
}

func TestCidrToBPFMapKey_InvalidCIDR(t *testing.T) {
	_, err := cidrToBPFMapKey("not-a-cidr")
	assert.Error(t, err)
}

func TestMappedIPv4CIDRKey(t *testing.T) {
	for _, tc := range []struct {
		cidr   string
		prefix uint32
		ip     string
	}{
		{"::ffff:192.0.2.1/96", 0, "0.0.0.0"},
		{"::ffff:192.0.2.1/120", 24, "192.0.2.0"},
		{"::ffff:192.0.2.1/128", 32, "192.0.2.1"},
		{"192.0.2.1/24", 24, "192.0.2.0"},
	} {
		address, err := cidrToBPFMapKey(tc.cidr)
		require.NoError(t, err)
		require.Len(t, address.key, 8)
		require.Equal(t, tc.prefix, binary.LittleEndian.Uint32(address.key[:4]))
		require.Equal(t, []byte(net.ParseIP(tc.ip).To4()), address.key[4:])
	}
	v6, err := cidrToBPFMapKey("2001:db8::1/64")
	require.NoError(t, err)
	require.Len(t, v6.key, 20)
	require.Equal(t, uint32(64), binary.LittleEndian.Uint32(v6.key[:4]))
}

func TestDomainMapRejectsInvalidIP(t *testing.T) {
	valid := net.ParseIP("192.0.2.1")
	for _, bad := range []net.IP{nil, {}, {192, 0, 2}, make(net.IP, 17)} {
		keys, err := domainNameToBPFMapKey("example.test", []net.IP{valid, bad})
		require.ErrorContains(t, err, "example.test")
		require.ErrorContains(t, err, "address 1")
		require.Nil(t, keys)
	}
	keys, err := domainNameToBPFMapKey("example.test", []net.IP{valid, net.ParseIP("2001:db8::1")})
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Len(t, keys[0].key, 8)
	require.Len(t, keys[1].key, 20)
}
