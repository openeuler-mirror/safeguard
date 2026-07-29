package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig_FileAccessDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.RestrictedFileAccessConfig.Enable)
	assert.Equal(t, "monitor", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, "host", cfg.RestrictedFileAccessConfig.Target)
	assert.Equal(t, []string{"/"}, cfg.RestrictedFileAccessConfig.Allow)
	assert.Equal(t, []string{}, cfg.RestrictedFileAccessConfig.Deny)
}

func TestDefaultConfig_MountDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.RestrictedMountConfig.Enable)
	assert.Equal(t, "monitor", cfg.RestrictedMountConfig.Mode)
	assert.Equal(t, "host", cfg.RestrictedMountConfig.Target)
	assert.Equal(t, []string{}, cfg.RestrictedMountConfig.DenySourcePath)
}

func TestDefaultConfig_ProcessDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.RestrictedProcessConfig.Enable)
	assert.Equal(t, "monitor", cfg.RestrictedProcessConfig.Mode)
	assert.Equal(t, "host", cfg.RestrictedProcessConfig.Target)
	assert.Equal(t, []string{}, cfg.RestrictedProcessConfig.Allow)
}
