package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByteToProcessKey(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "short process name",
			input:    []byte("bash"),
			expected: append([]byte("bash"), make([]byte, TASK_COMM_LEN-4)...),
		},
		{
			name:     "exact length",
			input:    []byte("1234567890123456"),
			expected: []byte("1234567890123456"),
		},
		{
			name:     "empty string",
			input:    []byte{},
			expected: make([]byte, TASK_COMM_LEN),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := byteToProcessKey(tt.input)
			assert.Equal(t, TASK_COMM_LEN, len(result))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDeniedProcessListConstants(t *testing.T) {
	assert.Equal(t, "denied_process_list", DENIED_PROCESS_LIST_MAP_NAME)
	assert.Equal(t, uint32(0), MODE_MONITOR)
	assert.Equal(t, uint32(1), MODE_BLOCK)
	assert.Equal(t, uint32(0), POLICY_BLACKLIST)
	assert.Equal(t, uint32(1), POLICY_WHITELIST)
}
