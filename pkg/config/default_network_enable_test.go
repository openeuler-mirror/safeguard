package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_NetworkDisabledByDefault(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.RestrictedNetworkConfig.Enable)
}
func TestDefaultConfig_NetworkModeIsMonitor(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "monitor", cfg.RestrictedNetworkConfig.Mode)
}
func TestDefaultConfig_NetworkTargetIsHost(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "host", cfg.RestrictedNetworkConfig.Target)
}
