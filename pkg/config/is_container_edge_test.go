package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsOnlyContainer_UnknownTarget(t *testing.T) {
	c := DefaultConfig()
	assert.False(t, c.IsOnlyContainer("unknown"))
}

func TestIsOnlyContainer_HostTarget(t *testing.T) {
	c := DefaultConfig()
	c.RestrictedNetworkConfig.Target = "host"
	assert.False(t, c.IsOnlyContainer("network"))
}
