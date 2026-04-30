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
