package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadProcProcesses_EmptyPathReturnsError(t *testing.T) {
	_, _, _, _, err := readProcProcesses("")
	assert.Error(t, err)
}

