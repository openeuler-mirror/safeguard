package fileaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_BlockedEvent(t *testing.T) {
	var event auditLog
	event.PID = 1234
	event.UID = 5678
	event.Ret = -1
	copy(event.Nodename[:], "testnode")
	copy(event.Command[:], "cat")
	copy(event.Path[:], "/etc/passwd")
	result := newAuditLog(event)
	assert.Equal(t, "BLOCKED", result.Action)
	assert.Equal(t, "/etc/passwd", result.Path)
	assert.Equal(t, uint32(1234), result.PID)
}
