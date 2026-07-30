package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateString(t *testing.T) {
	assert.Equal(t, "hello", truncateString("hello", 10))
	assert.Equal(t, "hel", truncateString("hello", 3))
	assert.Equal(t, "", truncateString("", 5))
}

func TestClampStrings(t *testing.T) {
	values := []string{"a", "b", "c"}
	result, truncated := clampStrings(values, 5)
	assert.Equal(t, values, result)
	assert.False(t, truncated)

	result, truncated = clampStrings(values, 2)
	assert.Equal(t, []string{"a", "b"}, result)
	assert.True(t, truncated)
}

func TestClampUints(t *testing.T) {
	values := []uint{1, 2, 3}
	result, truncated := clampUints(values, 5)
	assert.Equal(t, values, result)
	assert.False(t, truncated)

	result, truncated = clampUints(values, 2)
	assert.Equal(t, []uint{1, 2}, result)
	assert.True(t, truncated)
}
