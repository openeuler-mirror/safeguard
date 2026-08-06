package utils

import (
	"testing"
)

func TestReadSecurityLSM_DoesNotPanic(t *testing.T) {
	_, _ = readSecurityLSM()
}

