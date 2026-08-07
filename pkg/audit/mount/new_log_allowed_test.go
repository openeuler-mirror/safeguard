package mount

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_AllowedEvent(t *testing.T) {
	var event auditLog
	event.PID = 100
	event.Ret = 0
	copy(event.Nodename[:], "testnode")
	copy(event.Command[:], "mount")
	copy(event.MountSourcePath[:], "/dev/sda1")
	result := newAuditLog(event)
	assert.Equal(t, "ALLOWED", result.Action)
	assert.Equal(t, "/dev/sda1", result.SourcePath)
}
