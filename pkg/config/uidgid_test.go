package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_LoadsUIDAndGIDAllowDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uidgid.yaml")

	content := []byte(`network:
  mode: monitor
  uid:
    allow:
      - 0
      - 1000
    deny:
      - 65534
  gid:
    allow:
      - 0
    deny:
      - 65534
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []uint{0, 1000}, cfg.RestrictedNetworkConfig.UID.Allow)
	assert.Equal(t, []uint{65534}, cfg.RestrictedNetworkConfig.UID.Deny)
	assert.Equal(t, []uint{0}, cfg.RestrictedNetworkConfig.GID.Allow)
	assert.Equal(t, []uint{65534}, cfg.RestrictedNetworkConfig.GID.Deny)
}
