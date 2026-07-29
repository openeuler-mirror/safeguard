package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_LoadsDomainAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domain.yaml")

	content := []byte(`network:
  mode: monitor
  domain:
    allow:
      - example.com
      - trusted.org
    deny:
      - malicious.net
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com", "trusted.org"}, cfg.RestrictedNetworkConfig.Domain.Allow)
	assert.Equal(t, []string{"malicious.net"}, cfg.RestrictedNetworkConfig.Domain.Deny)
}
