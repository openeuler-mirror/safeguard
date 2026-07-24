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

func TestIsOnlyContainer_ForMountProcessAndUnknownTarget(t *testing.T) {
	config := DefaultConfig()

	config.RestrictedMountConfig.Target = "container"
	assert.True(t, config.IsOnlyContainer("mount"))

	config.RestrictedMountConfig.Target = "host"
	assert.False(t, config.IsOnlyContainer("mount"))

	config.RestrictedProcessConfig.Target = "container"
	assert.True(t, config.IsOnlyContainer("process"))

	config.RestrictedProcessConfig.Target = "host"
	assert.False(t, config.IsOnlyContainer("process"))

	assert.False(t, config.IsOnlyContainer("unknown"))
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

func TestIsRestrictedMode_ForMountProcessAndUnknownTarget(t *testing.T) {
	config := DefaultConfig()

	config.RestrictedMountConfig.Mode = "block"
	assert.True(t, config.IsRestrictedMode("mount"))

	config.RestrictedMountConfig.Mode = "monitor"
	assert.False(t, config.IsRestrictedMode("mount"))

	config.RestrictedProcessConfig.Mode = "block"
	assert.True(t, config.IsRestrictedMode("process"))

	config.RestrictedProcessConfig.Mode = "monitor"
	assert.False(t, config.IsRestrictedMode("process"))

	assert.False(t, config.IsRestrictedMode("unknown"))
}

func TestDefaultConfig_IncludesEmptyProcessAllowList(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, []string{}, cfg.RestrictedProcessConfig.Allow)
}

func TestDefaultConfig_IncludesDNSProxyAndLogDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.False(t, cfg.DNSProxyConfig.Enable)
	assert.Equal(t, []string{}, cfg.DNSProxyConfig.Upstreams)
	assert.Equal(t, []string{"127.0.0.1", "172.17.0.1"}, cfg.DNSProxyConfig.BindAddresses)
	assert.Equal(t, "INFO", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
	assert.Equal(t, "stdout", cfg.Log.Output)
	assert.Equal(t, map[string]string{}, cfg.Log.Labels)
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

func TestNewConfig_LoadsDNSProxyAndLogSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	content := []byte(`dns_proxy:
  enable: true
  upstreams:
    - 1.1.1.1
  bind:
    - 127.0.0.1
log:
  level: DEBUG
  format: text
  output: /tmp/safeguard.log
  max_size: 32
  max_age: 14
  labels:
    env: test
`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.True(t, cfg.DNSProxyConfig.Enable)
	assert.Equal(t, []string{"1.1.1.1"}, cfg.DNSProxyConfig.Upstreams)
	assert.Equal(t, []string{"127.0.0.1"}, cfg.DNSProxyConfig.BindAddresses)
	assert.Equal(t, "DEBUG", cfg.Log.Level)
	assert.Equal(t, "text", cfg.Log.Format)
	assert.Equal(t, "/tmp/safeguard.log", cfg.Log.Output)
	assert.Equal(t, 32, cfg.Log.MaxSize)
	assert.Equal(t, 14, cfg.Log.MaxAge)
	assert.Equal(t, map[string]string{"env": "test"}, cfg.Log.Labels)
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
