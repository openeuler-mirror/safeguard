package logger

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogger_ContainsSafeguardPid(t *testing.T) {
	entry := NewLogger()
	assert.NotNil(t, entry)
	pid, ok := entry.Data["safeguard_pid"]
	assert.True(t, ok)
	assert.Equal(t, os.Getpid(), pid)
}

func TestNewLogger_CreatesIndependentEntries(t *testing.T) {
	a := NewLogger()
	b := NewLogger()
	assert.Equal(t, a.Data["safeguard_pid"], b.Data["safeguard_pid"])
}
