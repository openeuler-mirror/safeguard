package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateString_ShorterThanLimit(t *testing.T) {
	assert.Equal(t, "abc", truncateString("abc", 10))
}

func TestTruncateString_ExactLimit(t *testing.T) {
	assert.Equal(t, "abcde", truncateString("abcde", 5))
}

func TestTruncateString_LongerThanLimit(t *testing.T) {
	assert.Equal(t, "abc", truncateString("abcdef", 3))
}
