package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestrictedNetworkLog_Info_DoesNotPanic(t *testing.T) {
	log := RestrictedNetworkLog{
		AuditEventLog: AuditEventLog{Module: "network", Action: "MONITOR", PID: 1},
		Addr:          "10.0.0.1",
		Port:          80,
		Protocol:      "TCP",
	}
	assert.NotPanics(t, func() { log.Info() })
}
