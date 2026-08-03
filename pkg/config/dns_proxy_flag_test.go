package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestConfig_EnableDNSProxy_DefaultFalse(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.EnableDNSProxy())
}
func TestConfig_EnableDNSProxy_WhenEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSProxyConfig.Enable = true
	assert.True(t, cfg.EnableDNSProxy())
}
