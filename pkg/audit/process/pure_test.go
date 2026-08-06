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
}
