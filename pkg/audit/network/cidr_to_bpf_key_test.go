package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
