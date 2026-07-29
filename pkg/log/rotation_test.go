package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetRotation_StdoutPathDoesNothing(t *testing.T) {
	prevOut := Logger.Logger.Out
	t.Cleanup(func() { Logger.Logger.Out = prevOut })

	assert.NotPanics(t, func() { SetRotation("stdout", 0, 0) })
	assert.NotPanics(t, func() { SetRotation("", 0, 0) })
}
