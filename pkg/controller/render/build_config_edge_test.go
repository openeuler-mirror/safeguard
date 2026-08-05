package render

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"culinux/pkg/controller/model"
)

func TestBuildConfig_MonitorModeSetsNetworkMode(t *testing.T) {
	w := model.WhitelistModel{}
	cfg := BuildConfig(w, "monitor")
	assert.Equal(t, "monitor", cfg.RestrictedNetworkConfig.Mode)
}
