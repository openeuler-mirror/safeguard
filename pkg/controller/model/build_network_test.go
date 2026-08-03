package model

import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestBuildNetworkWhitelist_Empty(t *testing.T) {
	wl, warnings := buildNetworkWhitelist(nil, nil, nil)
	assert.Empty(t, wl.CIDRAllow)
	assert.Empty(t, wl.UIDAllow)
	assert.Empty(t, wl.GIDAllow)
	assert.Empty(t, warnings)
}
func TestBuildNetworkWhitelist_WithUIDsAndGIDs(t *testing.T) {
	wl, _ := buildNetworkWhitelist(nil, []uint{1000, 0}, []uint{100})
	assert.Equal(t, []uint{0, 1000}, wl.UIDAllow)
	assert.Equal(t, []uint{100}, wl.GIDAllow)
}
