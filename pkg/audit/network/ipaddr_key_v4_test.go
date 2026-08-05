package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPAddress_ToBPFMapKey_IPv4(t *testing.T) {
	ip := IPAddress{address: net.ParseIP("10.0.0.0"), cidrMask: net.CIDRMask(24, 32)}
	key := ip.ipAddressToBPFMapKey()
	assert.NotNil(t, key)
	assert.Equal(t, 8, len(key))
}
