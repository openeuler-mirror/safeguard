package fileaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_AllowedEvent(t *testing.T) {
	var event auditLog
	event.PID = 100
	event.UID = 0
	event.Ret = 0
	copy(event.Nodename[:], "testnode")
	copy(event.Command[:], "cat")
	copy(event.Path[:], "/home/user/file.txt")
	result := newAuditLog(event)
	assert.Equal(t, "ALLOWED", result.Action)
	assert.Equal(t, "/home/user/file.txt", result.Path)
}
