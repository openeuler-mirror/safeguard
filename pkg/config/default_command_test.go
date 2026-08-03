package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_CommandAllowEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.Command.Allow)
}
func TestDefaultConfig_CommandDenyEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.Command.Deny)
}
