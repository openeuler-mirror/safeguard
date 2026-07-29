package logger
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestSetOutput_StdoutPath(t *testing.T) {
	origLogger := Logger.Logger.Out
	defer func() { Logger.Logger.Out = origLogger }()
	SetOutput("stdout")
	assert.NotNil(t, Logger.Logger.Out)
}
func TestSetOutput_EmptyPath(t *testing.T) {
	origLogger := Logger.Logger.Out
	defer func() { Logger.Logger.Out = origLogger }()
	SetOutput("")
	assert.NotNil(t, Logger.Logger.Out)
}
