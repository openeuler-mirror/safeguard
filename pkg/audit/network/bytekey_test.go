package network

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByteToKey_PadsTo16(t *testing.T) {
	input := []byte{1, 2, 3}
	key := byteToKey(input)
	assert.Equal(t, 16, len(key))
	assert.Equal(t, byte(1), key[0])
	assert.Equal(t, byte(0), key[3])
}

func TestUintToKey_EncodesLittleEndian(t *testing.T) {
	key := uintToKey(256)
	assert.Equal(t, 4, len(key))
	assert.Equal(t, uint32(256), binary.LittleEndian.Uint32(key))
}

