package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommToString_AllZeros(t *testing.T) {
	var comm [16]byte
	assert.Equal(t, "", CommToString(comm))
}

func TestCommToString_PartialFill(t *testing.T) {
	var comm [16]byte
	copy(comm[:], "sh")
	assert.Equal(t, "sh", CommToString(comm))
}
