package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRestrictedMode_BlockMode(t *testing.T) {
	c := DefaultConfig()
	c.RestrictedNetworkConfig.Mode = "block"
	assert.True(t, c.IsRestrictedMode("network"))
}

func TestIsRestrictedMode_FileAccessBlock(t *testing.T) {
	c := DefaultConfig()
	c.RestrictedFileAccessConfig.Mode = "block"
	assert.True(t, c.IsRestrictedMode("fileaccess"))
}
