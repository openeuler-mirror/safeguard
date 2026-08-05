package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4ToKey_24Prefix(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
	key := ipv4ToKey(*ipnet)
	assert.Equal(t, 8, len(key))
	assert.Equal(t, uint32(24), uint32(key[0])|uint32(key[1])<<8|uint32(key[2])<<16|uint32(key[3])<<24)
}

func TestIPv4ToKey_32Prefix(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.1/32")
	key := ipv4ToKey(*ipnet)
	assert.Equal(t, 8, len(key))
}

