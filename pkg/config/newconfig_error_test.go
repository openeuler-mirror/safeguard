package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestNewConfig_NonexistentFile(t *testing.T) {
	_, err := NewConfig("/nonexistent/path/safeguard.yaml")
	assert.Error(t, err)
}
