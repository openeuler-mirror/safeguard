package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "deduplicate and sort",
			input:    []string{"b", "a", "b", "a"},
			expected: []string{"a", "b"},
		},
		{
			name:     "trim whitespace",
			input:    []string{"  a  ", "b", "a"},
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueStrings(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUniqueUints(t *testing.T) {
	result := uniqueUints([]uint{3, 1, 2, 1, 3})
	assert.Equal(t, []uint{1, 2, 3}, result)
}

func TestBuildWhitelist(t *testing.T) {
	snapshot := HostSnapshot{
		Hostname: "test-host",
		CIDRs:    []string{"10.0.0.1/32"},
		Accounts: []Account{
			{Username: "root", UID: 0, GID: 0, HomeDir: "/root", Shell: "/bin/bash"},
		},
		UIDs:             []uint{0},
		GIDs:             []uint{0},
		RunningProcesses: []RunningProcess{},
		ExecutablePaths:  []string{},
		Warnings:         []string{},
	}

	result := BuildWhitelist(snapshot, time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC))

	assert.Equal(t, "test-host", result.Metadata.Hostname)
	assert.Contains(t, result.Files.Allow, "/")
	assert.Contains(t, result.Files.Allow, "/root")
}
