package collector

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterfaceAddressToCIDR_IPAddrType(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	cidr, ok := interfaceAddressToCIDR(addr)
	assert.True(t, ok)
	assert.Equal(t, "127.0.0.1/32", cidr)
}

func TestInterfaceAddressToCIDR_UDPAddrType(t *testing.T) {
	cidr, ok := interfaceAddressToCIDR(&net.UDPAddr{})
	assert.False(t, ok)
	assert.Empty(t, cidr)
}
