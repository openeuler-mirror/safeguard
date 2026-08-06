package utils

import (
	"testing"
)

func TestReadKernelConfig_DoesNotPanic(t *testing.T) {
	_, _ = readKernelConfig()
}

