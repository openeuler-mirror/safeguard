package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigValidate_Policy(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		wantErr bool
	}{
		{"valid blacklist", "blacklist", false},
		{"valid whitelist", "whitelist", false},
		{"invalid", "invalid", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			c.Policy = tt.policy
			err := c.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidate_Modes(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"valid monitor", "monitor", false},
		{"valid block", "block", false},
		{"invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			c.RestrictedNetworkConfig.Mode = tt.mode
			err := c.validateModes()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultConfig_HasDenyField(t *testing.T) {
	c := DefaultConfig()
	assert.NotNil(t, c.RestrictedProcessConfig.Deny)
	assert.NotNil(t, c.RestrictedFileAccessConfig.Deny)
}
