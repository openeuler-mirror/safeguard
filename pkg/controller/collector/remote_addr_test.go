package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoteAddressToCIDR_IPv4Loopback(t *testing.T) {
	result, err := remoteAddressToCIDR("0100007F:1F90")
	assert.NoError(t, err)
	assert.Contains(t, result, "127.0.0.1")
}

func TestRemoteAddressToCIDR_EmptyString(t *testing.T) {
	_, err := remoteAddressToCIDR("")
	assert.Error(t, err)
}

