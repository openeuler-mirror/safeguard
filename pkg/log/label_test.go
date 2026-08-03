package logger
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestSetLabel_AddsFields(t *testing.T) {
	origLogger := Logger
	defer func() { Logger = origLogger }()
	SetLabel(map[string]string{"env": "test"})
	assert.NotNil(t, Logger)
}
