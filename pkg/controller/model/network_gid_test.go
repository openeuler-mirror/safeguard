package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildNetworkWhitelist_WithGIDs(t *testing.T) {
	cidrs, warnings := buildNetworkWhitelist([]string{}, []uint{}, []uint{0, 1000})
	assert.Empty(t, cidrs.CIDRAllow)
	assert.Contains(t, cidrs.GIDAllow, uint(0))
	assert.Contains(t, cidrs.GIDAllow, uint(1000))
	assert.Empty(t, warnings)
}
