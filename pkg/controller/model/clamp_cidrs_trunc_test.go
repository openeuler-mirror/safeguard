package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClampCIDRs_IPv4Only(t *testing.T) {
	cidrs := make([]string, 10)
	for i := range cidrs { cidrs[i] = "10.0.0.0/8" }
	result, warnings := clampCIDRs(cidrs)
	// clampCIDRs does not deduplicate, all 10 are kept
	assert.Equal(t, 10, len(result))
	assert.Empty(t, warnings)
}

func TestClampCIDRs_MixedIPv4IPv6(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "2001:db8::/32"}
	result, warnings := clampCIDRs(cidrs)
	assert.Equal(t, 2, len(result))
	assert.Empty(t, warnings)
}

func TestClampCIDRs_InvalidCIDR(t *testing.T) {
	cidrs := []string{"not-a-cidr"}
	result, warnings := clampCIDRs(cidrs)
	assert.Equal(t, 1, len(result))
	assert.Empty(t, warnings)
}

