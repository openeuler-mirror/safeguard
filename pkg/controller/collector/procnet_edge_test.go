package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadProcNetCIDRs_NilPathsReturnsEmpty(t *testing.T) {
	result, warnings := readProcNetCIDRs(nil)
	assert.Empty(t, result)
	assert.Empty(t, warnings)
}

func TestReadProcNetCIDRs_NonexistentPath(t *testing.T) {
	result, warnings := readProcNetCIDRs([]string{"/nonexistent/path"})
	assert.Empty(t, result)
	assert.Len(t, warnings, 1)
}

