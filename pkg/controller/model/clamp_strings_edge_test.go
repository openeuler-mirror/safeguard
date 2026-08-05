package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClampStrings_NoTruncation(t *testing.T) {
	input := []string{"a", "b", "c"}
	result, truncated := clampStrings(input, 10)
	assert.Equal(t, input, result)
	assert.False(t, truncated)
}

func TestClampStrings_Truncation(t *testing.T) {
	input := []string{"a", "b", "c"}
	result, truncated := clampStrings(input, 2)
	assert.Equal(t, 2, len(result))
	assert.True(t, truncated)
}

func TestClampStrings_EmptyInput(t *testing.T) {
	result, truncated := clampStrings([]string{}, 5)
	assert.Empty(t, result)
	assert.False(t, truncated)
}
