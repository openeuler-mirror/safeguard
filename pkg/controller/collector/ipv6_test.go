package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteAddressToCIDR_IPv6Loopback(t *testing.T) {
	result, err := remoteAddressToCIDR("01000000000000000000000000000000:0035")
	require.NoError(t, err)
	assert.Equal(t, "::1/128", result)
}

func TestRemoteAddressToCIDR_IPv4PrivateAddress(t *testing.T) {
	result, err := remoteAddressToCIDR("0200000A:1F90")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2/32", result)
}
