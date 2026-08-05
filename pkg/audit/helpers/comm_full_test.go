package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommToString_FullLength(t *testing.T) {
	var comm [16]byte
	for i := 0; i < 16; i++ {
		comm[i] = 'a'
	}
	assert.Equal(t, "aaaaaaaaaaaaaaaa", CommToString(comm))
}

func TestCommToString_NullInMiddle(t *testing.T) {
	var comm [16]byte
	copy(comm[:], "bash")
	comm[4] = 0
	assert.Equal(t, "bash", CommToString(comm))
}
