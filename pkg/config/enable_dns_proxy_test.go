package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnableDNSProxy_Disabled(t *testing.T) {
	c := DefaultConfig()
	c.DNSProxyConfig.Enable = false
	assert.False(t, c.EnableDNSProxy())
}

func TestEnableDNSProxy_Enabled(t *testing.T) {
	c := DefaultConfig()
	c.DNSProxyConfig.Enable = true
	assert.True(t, c.EnableDNSProxy())
}
