package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_LoadsMountDenySourcePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mount.yaml")

	content := []byte(`mount:
  mode: block
  target: container
  deny:
    - /var/run/docker.sock
    - /proc/sysrq-trigger
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "block", cfg.RestrictedMountConfig.Mode)
	assert.Equal(t, "container", cfg.RestrictedMountConfig.Target)
	assert.Equal(t, []string{"/var/run/docker.sock", "/proc/sysrq-trigger"}, cfg.RestrictedMountConfig.DenySourcePath)
}
