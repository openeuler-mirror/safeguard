package logger

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSetLevel_WARNFallsBackToInfo(t *testing.T) {
	prevLevel := log.GetLevel()
	t.Cleanup(func() { log.SetLevel(prevLevel) })

	SetLevel("WARN")
	assert.Equal(t, log.InfoLevel, log.GetLevel())
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
