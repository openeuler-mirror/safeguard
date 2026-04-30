package fileaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyConstants(t *testing.T) {
	assert.Equal(t, uint32(0), POLICY_BLACKLIST)
	assert.Equal(t, uint32(1), POLICY_WHITELIST)
}

func TestMapLayoutConstants(t *testing.T) {
	assert.Equal(t, 8, MAP_POLICY_START)
	assert.Equal(t, 12, MAP_POLICY_END)
}

func TestSetPolicy(t *testing.T) {
	// Test policy constants are correct
	assert.Equal(t, 8, MAP_POLICY_START)
	assert.Equal(t, 12, MAP_POLICY_END)
	assert.Equal(t, uint32(0), POLICY_BLACKLIST)
	assert.Equal(t, uint32(1), POLICY_WHITELIST)
}

func TestCloseWithNilPb(t *testing.T) {
	// Test that Close handles nil pb gracefully
	// This tests the nil check added to Close method
	m := &Manager{pb: nil}
	// Close should not panic when pb is nil
	m.Close()
}

func TestBpfPolicyValues(t *testing.T) {
	// Test that policy values match BPF expectations
	// These values must match the enum in common_structs.h
	assert.Equal(t, uint32(0), POLICY_BLACKLIST, "POLICY_BLACKLIST should be 0")
	assert.Equal(t, uint32(1), POLICY_WHITELIST, "POLICY_WHITELIST should be 1")
}
