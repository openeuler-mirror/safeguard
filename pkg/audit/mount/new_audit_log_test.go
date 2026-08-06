package mount

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_MountEvent(t *testing.T) {
	var event auditLog
	event.PID = 999
	event.Ret = 1
	copy(event.Nodename[:], "host01")
	copy(event.Command[:], "mount")
	copy(event.MountSourcePath[:], "/dev/sda1")
	result := newAuditLog(event)
	assert.Equal(t, "MONITOR", result.Action)
	assert.Equal(t, "/dev/sda1", result.SourcePath)
	assert.Equal(t, uint32(999), result.PID)
}
