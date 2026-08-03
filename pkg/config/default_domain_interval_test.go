package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_DomainInterval(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, uint(5), cfg.RestrictedNetworkConfig.Domain.Interval)
}
