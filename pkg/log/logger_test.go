package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogLevel_Environment(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		input    string
		expected string
	}{
		{"env override", "DEBUG", "INFO", "DEBUG"},
		{"no env", "", "INFO", "INFO"},
		{"env empty", "", "DEBUG", "DEBUG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("SAFEGUARD_LOG", tt.envValue)
			}
			result := logLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetFormatter(t *testing.T) {
	// Test that SetFormatter doesn't panic
	assert.NotPanics(t, func() {
		SetFormatter("json")
	})
	assert.NotPanics(t, func() {
		SetFormatter("text")
	})
	assert.NotPanics(t, func() {
		SetFormatter("invalid")
	})
}

func TestNewLogger(t *testing.T) {
	entry := NewLogger()
	assert.NotNil(t, entry)
	assert.Contains(t, entry.Data, "safeguard_pid")
}
