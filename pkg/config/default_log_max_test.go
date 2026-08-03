package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_LogMaxSizeZero(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 0, cfg.Log.MaxSize)
}
func TestDefaultConfig_LogMaxAgeZero(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 0, cfg.Log.MaxAge)
}
