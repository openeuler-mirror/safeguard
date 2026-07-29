package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_LogLabelsEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.Log.Labels)
}
