package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRestrictedMode_UnknownTarget(t *testing.T) {
	c := DefaultConfig()
	assert.False(t, c.IsRestrictedMode("unknown"))
}

func TestIsRestrictedMode_MonitorMode(t *testing.T) {
	c := DefaultConfig()
	c.RestrictedNetworkConfig.Mode = "monitor"
	assert.False(t, c.IsRestrictedMode("network"))
}
