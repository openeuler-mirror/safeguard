package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv6ToKey_64Prefix(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("2001:db8::/64")
	key := ipv6ToKey(*ipnet)
	assert.Equal(t, 20, len(key))
}

func TestIPv6ToKey_128Prefix(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("::1/128")
	key := ipv6ToKey(*ipnet)
	assert.Equal(t, 20, len(key))
}

