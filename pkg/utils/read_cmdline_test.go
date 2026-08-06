package utils

import (
	"testing"
)

func TestReadCmdline_DoesNotPanic(t *testing.T) {
	_, _ = readCmdline()
}

