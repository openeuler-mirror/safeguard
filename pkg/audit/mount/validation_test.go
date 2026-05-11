package mount

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateMountPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"valid path", "/mnt/data", true},
		{"valid root", "/", true},
		{"invalid empty", "", false},
		{"invalid relative", "mnt/data", false},
		{"invalid too long", "/" + string(make([]byte, NAME_MAX)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateMountPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMountPolicyConstants(t *testing.T) {
	assert.Equal(t, uint32(0), POLICY_BLACKLIST)
	assert.Equal(t, uint32(1), POLICY_WHITELIST)
	assert.Equal(t, uint32(0), MODE_MONITOR)
	assert.Equal(t, uint32(1), MODE_BLOCK)
}
