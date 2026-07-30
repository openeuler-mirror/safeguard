package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_MinimalYAMLReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.yaml")
	require.NoError(t, os.WriteFile(path, []byte("policy: blacklist\n"), 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "blacklist", cfg.Policy)
	assert.False(t, cfg.RestrictedNetworkConfig.Enable)
	assert.False(t, cfg.RestrictedFileAccessConfig.Enable)
	assert.False(t, cfg.RestrictedMountConfig.Enable)
	assert.False(t, cfg.RestrictedProcessConfig.Enable)
}

func TestNewConfig_InvalidYAMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o644))

	_, err := NewConfig(path)
	require.Error(t, err)
}
