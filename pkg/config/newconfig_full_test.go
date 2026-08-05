package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig_FullYAML(t *testing.T) {
	f, _ := os.CreateTemp("", "config")
	defer os.Remove(f.Name())
	f.WriteString("policy: blacklist\nnetwork:\n  enable: true\n  mode: block\n  target: host\nfiles:\n  enable: true\n  mode: block\nmount:\n  enable: true\n  mode: block\nprocess:\n  enable: true\n  mode: block\ndns_proxy:\n  enable: true\n  upstreams:\n    - 8.8.8.8\n")
	f.Close()
	cfg, err := NewConfig(f.Name())
	assert.NoError(t, err)
	assert.True(t, cfg.RestrictedNetworkConfig.Enable)
	assert.Equal(t, "block", cfg.RestrictedNetworkConfig.Mode)
}
