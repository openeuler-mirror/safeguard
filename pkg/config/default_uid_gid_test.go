package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_UIDAllowEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.UID.Allow)
}
func TestDefaultConfig_GIDAllowEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.GID.Allow)
}
