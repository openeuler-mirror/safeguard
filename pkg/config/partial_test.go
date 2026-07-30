package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_PartialOverridePreservesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.yaml")

	content := []byte(`policy: whitelist
network:
  mode: block
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "whitelist", cfg.Policy)
	assert.Equal(t, "block", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "host", cfg.RestrictedNetworkConfig.Target)
	assert.Equal(t, "monitor", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, "monitor", cfg.RestrictedMountConfig.Mode)
	assert.Equal(t, "monitor", cfg.RestrictedProcessConfig.Mode)
}
