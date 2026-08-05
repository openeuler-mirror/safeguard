package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildNetworkWhitelist_WithCIDRs(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "192.168.0.0/16"}
	wl, _ := buildNetworkWhitelist(cidrs, nil, nil)
	assert.Equal(t, cidrs, wl.CIDRAllow)
}

func TestBuildNetworkWhitelist_WithInvalidCIDR(t *testing.T) {
	cidrs := []string{"not-a-cidr"}
	wl, _ := buildNetworkWhitelist(cidrs, nil, nil)
	assert.Contains(t, wl.CIDRAllow, "not-a-cidr")
}

