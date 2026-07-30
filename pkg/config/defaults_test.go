package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig_NetworkDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.RestrictedNetworkConfig.Enable)
	assert.Equal(t, "monitor", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "host", cfg.RestrictedNetworkConfig.Target)
	assert.Equal(t, []string{"0.0.0.0/0", "::/0"}, cfg.RestrictedNetworkConfig.CIDR.Allow)
	assert.Equal(t, []string{}, cfg.RestrictedNetworkConfig.CIDR.Deny)
	assert.Equal(t, []string{}, cfg.RestrictedNetworkConfig.Domain.Allow)
	assert.Equal(t, []string{}, cfg.RestrictedNetworkConfig.Domain.Deny)
	assert.Equal(t, uint(5), cfg.RestrictedNetworkConfig.Domain.Interval)
	assert.Equal(t, []uint{}, cfg.RestrictedNetworkConfig.UID.Allow)
	assert.Equal(t, []uint{}, cfg.RestrictedNetworkConfig.UID.Deny)
	assert.Equal(t, []uint{}, cfg.RestrictedNetworkConfig.GID.Allow)
	assert.Equal(t, []uint{}, cfg.RestrictedNetworkConfig.GID.Deny)
	assert.Equal(t, []string{}, cfg.RestrictedNetworkConfig.Command.Allow)
	assert.Equal(t, []string{}, cfg.RestrictedNetworkConfig.Command.Deny)
}
