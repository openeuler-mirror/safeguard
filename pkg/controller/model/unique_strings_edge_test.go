package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUniqueStrings_EmptyInput(t *testing.T) {
	assert.Empty(t, uniqueStrings([]string{}))
}

func TestUniqueStrings_SingleElement(t *testing.T) {
	assert.Equal(t, []string{"a"}, uniqueStrings([]string{"a"}))
}

func TestUniqueStrings_AllWhitespace(t *testing.T) {
	assert.Empty(t, uniqueStrings([]string{" ", "  ", "\t"}))
}
