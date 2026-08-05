package network

import (
	"testing"

	"culinux/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestCreateDNSConfig_SetsUpstreams(t *testing.T) {
	cfg := config.DNSProxyConfig{Upstreams: []string{"8.8.8.8", "1.1.1.1"}}
	result, err := createDNSConfig(cfg)
	assert.NoError(t, err)
	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, result.Servers)
}
