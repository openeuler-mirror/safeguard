package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadProcNetCIDRs_EmptyPathsReturnsEmpty(t *testing.T) {
	result, warnings := readProcNetCIDRs([]string{})
	assert.Empty(t, result)
	assert.Empty(t, warnings)
}

func TestReadProcNetCIDRs_MissingFileProducesWarning(t *testing.T) {
	result, warnings := readProcNetCIDRs([]string{"/nonexistent/net/tcp"})
	assert.Empty(t, result)
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "unreadable")
}
