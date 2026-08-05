package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_ProcessEvent(t *testing.T) {
	var event auditLog
	event.PID = 1111
	event.PPID = 1
	copy(event.Nodename[:], "worknode")
	copy(event.Command[:], "bash")
	result := newAuditLog(event)
	assert.Equal(t, "process", result.Module)
	assert.Equal(t, uint32(1111), result.PID)
	assert.Equal(t, uint32(1), result.PPID)
}
