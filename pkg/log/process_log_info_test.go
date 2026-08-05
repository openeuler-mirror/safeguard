package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestrictedProcessLog_Info_DoesNotPanic(t *testing.T) {
	log := RestrictedProcessLog{
		AuditEventLog: AuditEventLog{Module: "process", PID: 1},
		PPID:          0,
	}
	assert.NotPanics(t, func() { log.Info() })
}
