package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPAddress_IsV6address_True(t *testing.T) {
	ip := IPAddress{address: net.ParseIP("2001:db8::1")}
	assert.True(t, ip.isV6address())
}

func TestIPAddress_IsV6address_False(t *testing.T) {
	ip := IPAddress{address: net.ParseIP("10.0.0.1")}
	assert.False(t, ip.isV6address())
}
