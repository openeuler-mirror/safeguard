package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildNetworkWhitelist_EmptyInputs(t *testing.T) {
	cidrs, warnings := buildNetworkWhitelist([]string{}, []uint{}, []uint{})
	assert.Empty(t, cidrs.CIDRAllow)
	assert.Empty(t, cidrs.UIDAllow)
	assert.Empty(t, cidrs.GIDAllow)
	assert.Empty(t, warnings)
}
