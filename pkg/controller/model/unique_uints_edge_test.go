package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUniqueUints_EmptyInput(t *testing.T) {
	assert.Empty(t, uniqueUints([]uint{}))
}

func TestUniqueUints_SingleElement(t *testing.T) {
	assert.Equal(t, []uint{1}, uniqueUints([]uint{1}))
}

func TestUniqueUints_Sorted(t *testing.T) {
	result := uniqueUints([]uint{3, 1, 2})
	assert.Equal(t, []uint{1, 2, 3}, result)
}
