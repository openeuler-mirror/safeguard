package utils

import (
	"testing"
)

func TestHasBPFLSM_DoesNotPanic(t *testing.T) {
	_ = hasBPFLSM()
}

