package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_LoadsNetworkCIDRAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network-cidr.yaml")

	content := []byte(`network:
  mode: monitor
  target: host
  cidr:
    allow:
      - 10.0.0.0/8
      - 192.168.0.0/16
    deny:
      - 10.0.0.1/32
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, cfg.RestrictedNetworkConfig.CIDR.Allow)
	assert.Equal(t, []string{"10.0.0.1/32"}, cfg.RestrictedNetworkConfig.CIDR.Deny)
}

func TestNewConfig_LoadsNetworkModeAndTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network-mode.yaml")

	content := []byte(`network:
  mode: block
  target: container
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "block", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "container", cfg.RestrictedNetworkConfig.Target)
}
