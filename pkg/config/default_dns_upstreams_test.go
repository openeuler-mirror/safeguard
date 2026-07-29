package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_DNSProxyUpstreamsEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.DNSProxyConfig.Upstreams)
}
