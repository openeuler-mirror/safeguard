package logger

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetLabel_AddsFields(t *testing.T) {
	origLogger := Logger
	defer func() { Logger = origLogger }()
	SetLabel(map[string]string{"env": "test"})
	assert.NotNil(t, Logger)
}

func TestSetLabelPreservesProcessID(t *testing.T) {
	previous := Logger
	t.Cleanup(func() { Logger = previous })
	Logger = NewLogger()
	SetLabel(map[string]string{"safeguard_pid": "spoofed", "env": "test"})
	assert.Equal(t, os.Getpid(), Logger.Data["safeguard_pid"])
	assert.Equal(t, "test", Logger.Data["env"])
}
