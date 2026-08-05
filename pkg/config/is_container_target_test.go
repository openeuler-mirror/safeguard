package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsOnlyContainer_ContainerTarget(t *testing.T) {
	c := DefaultConfig()
	c.RestrictedNetworkConfig.Target = "container"
	assert.True(t, c.IsOnlyContainer("network"))
}

func TestIsOnlyContainer_FileAccessContainer(t *testing.T) {
	c := DefaultConfig()
	c.RestrictedFileAccessConfig.Target = "container"
	assert.True(t, c.IsOnlyContainer("fileaccess"))
}
