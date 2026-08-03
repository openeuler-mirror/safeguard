package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_NetworkCIDRAllowIncludesV4AndV6(t *testing.T) {
	cfg := DefaultConfig()
	assert.Contains(t, cfg.RestrictedNetworkConfig.CIDR.Allow, "0.0.0.0/0")
	assert.Contains(t, cfg.RestrictedNetworkConfig.CIDR.Allow, "::/0")
}
func TestDefaultConfig_NetworkCIDRDenyEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.CIDR.Deny)
}
