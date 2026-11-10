package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewLogger_ContainsSafeguardPid(t *testing.T) {
	entry := NewLogger()
	assert.NotNil(t, entry)
	pid, ok := entry.Data["safeguard_pid"]
	assert.True(t, ok)
	assert.Equal(t, os.Getpid(), pid)
}

func TestNewLogger_CreatesIndependentEntries(t *testing.T) {
	a := NewLogger()
	b := NewLogger()
	assert.Equal(t, a.Data["safeguard_pid"], b.Data["safeguard_pid"])
}

func TestWithFieldsPreservesPersistentLabels(t *testing.T) {
	previous := Logger
	t.Cleanup(func() { Logger = previous })
	Logger = NewLogger()
	SetLabel(map[string]string{"cluster": "test", "source": "default"})
	entry := WithFields(log.Fields{"source": "event", "action": "blocked"})
	assert.Equal(t, os.Getpid(), entry.Data["safeguard_pid"])
	assert.Equal(t, "test", entry.Data["cluster"])
	assert.Equal(t, "event", entry.Data["source"])
	assert.Equal(t, "blocked", entry.Data["action"])
	assert.Equal(t, "default", Logger.Data["source"])
	assert.NotContains(t, Logger.Data, "action")
	output, formatter, level := Logger.Logger.Out, Logger.Logger.Formatter, Logger.Logger.GetLevel()
	t.Cleanup(func() {
		Logger.Logger.SetOutput(output)
		Logger.Logger.SetFormatter(formatter)
		Logger.Logger.SetLevel(level)
	})
	var buffer bytes.Buffer
	Logger.Logger.SetOutput(&buffer)
	Logger.Logger.SetFormatter(&log.JSONFormatter{})
	Logger.Logger.SetLevel(log.InfoLevel)
	entry.Info("event")
	var record map[string]interface{}
	assert.NoError(t, json.Unmarshal(buffer.Bytes(), &record))
	assert.Equal(t, "test", record["cluster"])
	assert.Equal(t, "event", record["source"])
}
