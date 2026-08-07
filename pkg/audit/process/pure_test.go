package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByteToProcessKey_PadsToTaskCommLen(t *testing.T) {
	input := []byte("bash")
	result := byteToProcessKey(input)
	assert.Equal(t, TASK_COMM_LEN, len(result))
	assert.Equal(t, []byte("bash"), result[:4])
	assert.Equal(t, byte(0), result[4])
}

func TestByteToProcessKey_LongInput(t *testing.T) {
	input := []byte("verylongprocessname")
	result := byteToProcessKey(input)
	assert.Equal(t, TASK_COMM_LEN, len(result))
	// Inputs longer than 15 bytes are truncated to 15, leaving
	// byte 15 as NUL so the kernel-side task_struct.comm comparison
	// can match. Filling all 16 bytes (the previous behavior) would
	// drop the terminator and the entry would never match.
	assert.Equal(t, []byte("verylongprocessn"), result[:maxCommandNameLen])
	assert.Equal(t, byte(0), result[maxCommandNameLen])
}

func TestByteToProcessKey_Exactly15Bytes(t *testing.T) {
	input := []byte("exactly15bytes")
	result := byteToProcessKey(input)
	assert.Equal(t, TASK_COMM_LEN, len(result))
	assert.Equal(t, []byte("exactly15bytes"), result[:maxCommandNameLen])
	assert.Equal(t, byte(0), result[maxCommandNameLen])
}
