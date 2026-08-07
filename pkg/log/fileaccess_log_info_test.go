package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestrictedFileAccessLog_Info_DoesNotPanic(t *testing.T) {
	log := RestrictedFileAccessLog{
		AuditEventLog: AuditEventLog{Module: "access", Action: "BLOCKED", PID: 1},
		Path:          "/etc/passwd",
	}
	assert.NotPanics(t, func() { log.Info() })
}
