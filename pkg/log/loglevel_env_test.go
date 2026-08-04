package logger

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogLevel_EnvOverrides(t *testing.T) {
	os.Setenv("SAFEGUARD_LOG", "custom")
	defer os.Unsetenv("SAFEGUARD_LOG")
	assert.Equal(t, "custom", logLevel("debug"))
}

func TestLogLevel_NoEnvUppercases(t *testing.T) {
	os.Unsetenv("SAFEGUARD_LOG")
	assert.Equal(t, "DEBUG", logLevel("debug"))
}
