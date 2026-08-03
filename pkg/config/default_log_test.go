package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_LogLevel(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "INFO", cfg.Log.Level)
}
func TestDefaultConfig_LogFormat(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "json", cfg.Log.Format)
}
func TestDefaultConfig_LogOutput(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "stdout", cfg.Log.Output)
}
