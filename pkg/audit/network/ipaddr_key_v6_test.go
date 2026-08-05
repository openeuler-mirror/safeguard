package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPAddress_ToBPFMapKey_IPv6(t *testing.T) {
	ip := IPAddress{address: net.ParseIP("2001:db8::"), cidrMask: net.CIDRMask(64, 128)}
	key := ip.ipAddressToBPFMapKey()
	assert.NotNil(t, key)
	assert.Equal(t, 20, len(key))
}
