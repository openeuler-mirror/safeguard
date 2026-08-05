package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodenameToString_AllZeros(t *testing.T) {
	var name [65]byte
	assert.Equal(t, "", NodenameToString(name))
}

func TestNodenameToString_FullLength(t *testing.T) {
	var name [65]byte
	for i := 0; i < 64; i++ {
		name[i] = 'a'
	}
	assert.Equal(t, string(name[:64]), NodenameToString(name))
}
