package fileaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"valid absolute path", "/etc/passwd", true},
		{"valid root path", "/", true},
		{"valid nested path", "/var/log/app.log", true},
		{"invalid empty", "", false},
		{"invalid relative", "etc/passwd", false},
		{"invalid relative dot", "./file", false},
		{"invalid relative double dot", "../file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterValidPaths(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected []string
	}{
		{"all valid", []string{"/etc/passwd", "/var/log"}, []string{"/etc/passwd", "/var/log"}},
		{"mixed", []string{"/etc/passwd", "invalid", "/var/log"}, []string{"/etc/passwd", "/var/log"}},
		{"all invalid", []string{"invalid", "relative"}, nil},
		{"empty", []string{}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterValidPaths(tt.paths)
			assert.Equal(t, tt.expected, result)
		})
	}
}
