package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_LoadsFileAccessAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileaccess.yaml")

	content := []byte(`files:
  mode: block
  target: host
  allow:
    - /etc/passwd
    - /var/log
  deny:
    - /etc/shadow
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/passwd", "/var/log"}, cfg.RestrictedFileAccessConfig.Allow)
	assert.Equal(t, []string{"/etc/shadow"}, cfg.RestrictedFileAccessConfig.Deny)
	assert.Equal(t, "block", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, "host", cfg.RestrictedFileAccessConfig.Target)
}
