package model

import (
	"testing"

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
