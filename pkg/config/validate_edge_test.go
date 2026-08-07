package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate_DNSProxyEnabledWithUpstreams(t *testing.T) {
	c := DefaultConfig()
	c.DNSProxyConfig.Enable = true
	c.DNSProxyConfig.Upstreams = []string{"8.8.8.8"}
	assert.NoError(t, c.Validate())
}
