package logger

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestSetOutputClosesOnlyOwnedFiles(t *testing.T) {
	previous := Logger.Logger.Out
	t.Cleanup(func() { SetOutput("stdout"); Logger.Logger.SetOutput(previous) })
	path := filepath.Join(t.TempDir(), "audit.log")
	assert.NoError(t, SetOutput(path))
	first := Logger.Logger.Out.(*os.File)
	assert.Error(t, SetOutput(filepath.Join(path, "missing")))
	_, err := first.WriteString("still open\n")
	assert.NoError(t, err)
	SetRotation(path, 1, 1)
	_, err = first.WriteString("closed\n")
	assert.ErrorIs(t, err, os.ErrClosed)
	assert.NoError(t, SetOutput(path))
	second := Logger.Logger.Out.(*os.File)
	assert.NoError(t, SetOutput("stdout"))
	_, err = second.WriteString("closed\n")
	assert.ErrorIs(t, err, os.ErrClosed)
	_, err = os.Stdout.Write(nil)
	assert.NoError(t, err)
}
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
