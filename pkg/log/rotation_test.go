package logger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetOutputClosesRotatingFile(t *testing.T) {
	previous := Logger.Logger.Out
	t.Cleanup(func() { SetOutput("stdout"); Logger.Logger.SetOutput(previous) })
	path := filepath.Join(t.TempDir(), "audit.log")
	SetRotation(path, 1, 1)
	Logger.Info("open rotating log")
	openFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		require.NoError(t, err)
		count := 0
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil && target == path {
				count++
			}
		}
		return count
	}
	require.Positive(t, openFDs())
	require.NoError(t, SetOutput("stdout"))
	assert.Zero(t, openFDs())
}

func TestSetRotation_StdoutPathDoesNothing(t *testing.T) {
	prevOut := Logger.Logger.Out
	t.Cleanup(func() { Logger.Logger.Out = prevOut })

	assert.NotPanics(t, func() { SetRotation("stdout", 0, 0) })
	assert.NotPanics(t, func() { SetRotation("", 0, 0) })
}
