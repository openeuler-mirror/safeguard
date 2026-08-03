package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_ProcessAllowEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedProcessConfig.Allow)
}
func TestDefaultConfig_ProcessDisabledByDefault(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.RestrictedProcessConfig.Enable)
}
