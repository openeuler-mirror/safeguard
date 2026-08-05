package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestrictedMountLog_Info_DoesNotPanic(t *testing.T) {
	log := RestrictedMountLog{
		AuditEventLog: AuditEventLog{Module: "mount", Action: "MONITOR", PID: 1},
		SourcePath:    "/dev/sda1",
	}
	assert.NotPanics(t, func() { log.Info() })
}
