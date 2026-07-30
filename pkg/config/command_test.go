package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_LoadsCommandAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command.yaml")

	content := []byte(`network:
  mode: monitor
  command:
    allow:
      - curl
      - wget
    deny:
      - ncat
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"curl", "wget"}, cfg.RestrictedNetworkConfig.Command.Allow)
	assert.Equal(t, []string{"ncat"}, cfg.RestrictedNetworkConfig.Command.Deny)
}
