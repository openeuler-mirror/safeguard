package render

import (
	"testing"

	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
)

func TestBuildConfig_BlockModeSetsAllModules(t *testing.T) {
	cfg := BuildConfig(model.WhitelistModel{}, "block")

	assert.Equal(t, "block", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedProcessConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedMountConfig.Mode)
	assert.Equal(t, "whitelist", cfg.Policy)
}

func TestBuildConfig_MonitorModeSetsAllModules(t *testing.T) {
	cfg := BuildConfig(model.WhitelistModel{}, "monitor")

	assert.Equal(t, "monitor", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "monitor", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, "monitor", cfg.RestrictedProcessConfig.Mode)
	assert.Equal(t, "monitor", cfg.RestrictedMountConfig.Mode)
}
