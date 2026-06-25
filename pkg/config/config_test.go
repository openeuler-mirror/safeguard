package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsOnlyContainer(t *testing.T) {
	config := DefaultConfig()

	t.Run("For network", func(t *testing.T) {
		t.Run("When target is container, should be return true", func(t *testing.T) {
			config.RestrictedNetworkConfig.Target = "container"
			assert.Equal(t, config.IsOnlyContainer("network"), true)
		})

		t.Run("When target is host, should be return false", func(t *testing.T) {
			config.RestrictedNetworkConfig.Target = "host"
			assert.Equal(t, config.IsOnlyContainer("network"), false)
		})
	})

	t.Run("For fileaccess", func(t *testing.T) {
		t.Run("When target is container, should be return true", func(t *testing.T) {
			config.RestrictedFileAccessConfig.Target = "container"
			assert.Equal(t, config.IsOnlyContainer("fileaccess"), true)
		})

		t.Run("When target is host, should be return false", func(t *testing.T) {
			config.RestrictedFileAccessConfig.Target = "host"
			assert.Equal(t, config.IsOnlyContainer("fileaccess"), false)
		})
	})
}

func TestIsRestrictedMode(t *testing.T) {
	config := DefaultConfig()

	t.Run("For network", func(t *testing.T) {
		t.Run("When mode is block, should be return true", func(t *testing.T) {
			config.RestrictedNetworkConfig.Mode = "block"
			assert.Equal(t, config.IsRestrictedMode("network"), true)
		})

		t.Run("When mode is monitor, should be return false", func(t *testing.T) {
			config.RestrictedNetworkConfig.Mode = "monitor"
			assert.Equal(t, config.IsRestrictedMode("network"), false)
		})
	})

	t.Run("For fileaccess", func(t *testing.T) {
		t.Run("When mode is block, should be return true", func(t *testing.T) {
			config.RestrictedFileAccessConfig.Mode = "block"
			assert.Equal(t, config.IsRestrictedMode("fileaccess"), true)
		})

		t.Run("When mode is monitor, should be return false", func(t *testing.T) {
			config.RestrictedFileAccessConfig.Mode = "monitor"
			assert.Equal(t, config.IsRestrictedMode("fileaccess"), false)
		})
	})
}

func TestDefaultConfig_IncludesEmptyProcessAllowList(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, []string{}, cfg.RestrictedProcessConfig.Allow)
}

func TestNewConfig_LoadsProcessAllowList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "process-allow.yaml")

	content := []byte(`process:
  mode: monitor
  target: host
  allow:
    - bash
    - sshd
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"bash", "sshd"}, cfg.RestrictedProcessConfig.Allow)
}

func TestDefaultConfig_PolicyIsBlacklist(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "blacklist", cfg.Policy)
}

func TestNewConfig_LoadsPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	content := []byte(`policy: whitelist
network:
  mode: monitor
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "whitelist", cfg.Policy)
}

func TestNewConfig_RequiresDNSProxyUpstreams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns-proxy.yaml")

	content := []byte(`dns_proxy:
  enable: true
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	_, err := NewConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dns_proxy.upstreams")
}
