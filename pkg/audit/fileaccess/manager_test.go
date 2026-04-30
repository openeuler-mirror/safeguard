package fileaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyConstants(t *testing.T) {
	assert.Equal(t, uint32(0), POLICY_BLACKLIST)
	assert.Equal(t, uint32(1), POLICY_WHITELIST)
}
