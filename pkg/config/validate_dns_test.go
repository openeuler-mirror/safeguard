package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestConfig_Validate_DNSProxyEnabledNoUpstreams(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSProxyConfig.Enable = true
	cfg.DNSProxyConfig.Upstreams = []string{}
	err := cfg.Validate()
	assert.Error(t, err)
}
func TestConfig_Validate_DNSProxyEnabledWithUpstreams(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSProxyConfig.Enable = true
	cfg.DNSProxyConfig.Upstreams = []string{"8.8.8.8"}
	err := cfg.Validate()
	assert.NoError(t, err)
}
