package logger

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogLevel_Environment(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		input    string
		expected string
	}{
		{"env override", "DEBUG", "INFO", "DEBUG"},
		{"no env", "", "INFO", "INFO"},
		{"env empty", "", "DEBUG", "DEBUG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("SAFEGUARD_LOG", tt.envValue)
			}
			result := logLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetFormatter(t *testing.T) {
	// Test that SetFormatter doesn't panic
	assert.NotPanics(t, func() {
		SetFormatter("json")
	})
	assert.NotPanics(t, func() {
		SetFormatter("text")
	})
	assert.NotPanics(t, func() {
		SetFormatter("invalid")
	})
}

func TestNewLogger(t *testing.T) {
	entry := NewLogger()
	assert.NotNil(t, entry)
	assert.Contains(t, entry.Data, "safeguard_pid")
}

func TestSetLevelAndFormatter(t *testing.T) {
	prevLogger := Logger
	prevLevel := log.GetLevel()
	prevFormatter := Logger.Logger.Formatter
	t.Cleanup(func() {
		Logger = prevLogger
		log.SetLevel(prevLevel)
		log.SetFormatter(prevFormatter)
	})

	SetLevel("TRACE")
	assert.Equal(t, log.TraceLevel, log.GetLevel())
	SetLevel("invalid")
	assert.Equal(t, log.InfoLevel, log.GetLevel())

	SetFormatter("text")
	_, ok := Logger.Logger.Formatter.(*log.TextFormatter)
	assert.True(t, ok)
	SetFormatter("invalid")
	_, ok = Logger.Logger.Formatter.(*log.JSONFormatter)
	assert.True(t, ok)
}

func TestSetOutputAndLabel(t *testing.T) {
	prevLogger := Logger
	prevOut := Logger.Logger.Out
	t.Cleanup(func() {
		Logger = prevLogger
		Logger.Logger.Out = prevOut
	})

	Logger = NewLogger()
	SetLabel(map[string]string{"env": "test"})
	assert.Equal(t, "test", Logger.Data["env"])

	path := t.TempDir() + "/safeguard.log"
	SetOutput(path)
	file, ok := Logger.Logger.Out.(*os.File)
	require.True(t, ok)
	assert.Equal(t, path, file.Name())

	SetOutput("stdout")
	assert.Equal(t, os.Stdout, Logger.Logger.Out)
}
