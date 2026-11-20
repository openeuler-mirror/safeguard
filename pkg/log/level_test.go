package logger

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSetLevelSupportedLevels(t *testing.T) {
	prevLevel := log.GetLevel()
	t.Cleanup(func() { log.SetLevel(prevLevel) })
	t.Setenv("SAFEGUARD_LOG", "")
	for _, tc := range []struct {
		input string
		want  log.Level
	}{
		{"warn", log.WarnLevel}, {"WARNING", log.WarnLevel},
		{"error", log.ErrorLevel}, {"fatal", log.FatalLevel}, {"panic", log.PanicLevel},
	} {
		SetLevel(tc.input)
		assert.Equal(t, tc.want, log.GetLevel(), tc.input)
	}
	t.Setenv("SAFEGUARD_LOG", "dEbUg")
	SetLevel("ERROR")
	assert.Equal(t, log.DebugLevel, log.GetLevel())
	t.Setenv("SAFEGUARD_LOG", "unknown")
	assert.Error(t, SetLevel("INFO"))
	assert.Equal(t, log.DebugLevel, log.GetLevel())
}

func TestSetLevel_DebugLevel(t *testing.T) {
	prevLevel := log.GetLevel()
	t.Cleanup(func() { log.SetLevel(prevLevel) })

	SetLevel("DEBUG")
	assert.Equal(t, log.DebugLevel, log.GetLevel())
}

func TestLogLevel_UppercasesInput(t *testing.T) {
	result := logLevel("debug")
	assert.Equal(t, "DEBUG", result)
}

func TestSetFormatter_JSONIsDefaultForInvalid(t *testing.T) {
	prevFormatter := Logger.Logger.Formatter
	t.Cleanup(func() { Logger.Logger.Formatter = prevFormatter })

	SetFormatter("yaml")
	_, ok := Logger.Logger.Formatter.(*log.JSONFormatter)
	assert.True(t, ok)
}

func TestSetFormatterAcceptsMixedCase(t *testing.T) {
	previous := Logger.Logger.Formatter
	t.Cleanup(func() { Logger.Logger.SetFormatter(previous) })
	SetFormatter("TeXt")
	_, ok := Logger.Logger.Formatter.(*log.TextFormatter)
	assert.True(t, ok)
}
