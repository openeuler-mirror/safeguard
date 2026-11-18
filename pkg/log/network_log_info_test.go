package logger

import (
	"bytes"
	"encoding/json"
	"testing"

	logrus "github.com/sirupsen/logrus"
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

func TestNetworkLogIncludesUID(t *testing.T) {
	previous, formatter, level := Logger.Logger.Out, Logger.Logger.Formatter, Logger.Logger.GetLevel()
	t.Cleanup(func() {
		Logger.Logger.SetOutput(previous)
		Logger.Logger.SetFormatter(formatter)
		Logger.Logger.SetLevel(level)
	})
	var output bytes.Buffer
	Logger.Logger.SetOutput(&output)
	Logger.Logger.SetFormatter(&logrus.JSONFormatter{})
	Logger.Logger.SetLevel(logrus.InfoLevel)
	entry := RestrictedNetworkLog{AuditEventLog: AuditEventLog{Module: "network", UID: 1234}}
	entry.Info()
	var record map[string]interface{}
	assert.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, float64(1234), record["UID"])
}
