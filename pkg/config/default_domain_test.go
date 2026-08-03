package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_DomainAllowEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.Domain.Allow)
}
func TestDefaultConfig_DomainDenyEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedNetworkConfig.Domain.Deny)
}
