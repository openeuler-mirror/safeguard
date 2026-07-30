package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClampCIDRs_SeparatesIPv4AndIPv6(t *testing.T) {
	result, warnings := clampCIDRs([]string{"10.0.0.0/8", "2001:db8::/32", "not-a-cidr"})
	assert.Equal(t, []string{"10.0.0.0/8", "2001:db8::/32", "not-a-cidr"}, result)
	assert.Empty(t, warnings)
}

func TestClampCIDRs_OnlyIPv4(t *testing.T) {
	result, warnings := clampCIDRs([]string{"10.0.0.0/8", "192.168.0.0/16"})
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, result)
	assert.Empty(t, warnings)
}

func TestClampCIDRs_OnlyIPv6(t *testing.T) {
	result, warnings := clampCIDRs([]string{"2001:db8::/32", "fe80::/10"})
	assert.Equal(t, []string{"2001:db8::/32", "fe80::/10"}, result)
	assert.Empty(t, warnings)
}
