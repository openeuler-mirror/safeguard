package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig_DNSProxyBindAddresses(t *testing.T) {
	cfg := DefaultConfig()
	assert.Contains(t, cfg.DNSProxyConfig.BindAddresses, "127.0.0.1")
}

