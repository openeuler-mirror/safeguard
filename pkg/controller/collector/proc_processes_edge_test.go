package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadProcProcesses_NonexistentRoot(t *testing.T) {
	processes, _, _, _, err := readProcProcesses("/nonexistent/proc")
	assert.Error(t, err)
	assert.Empty(t, processes)
}
