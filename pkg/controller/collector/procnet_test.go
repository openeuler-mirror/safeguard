package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestReadProcNetCIDRs_ReportsScanFailureAndContinues(t *testing.T) {
	root := t.TempDir()
	broken, valid := filepath.Join(root, "tcp"), filepath.Join(root, "udp")
	content := "header\n0: ignored 0100007F:0035\n" + strings.Repeat("x", 65536) + "\n"
	require.NoError(t, os.WriteFile(broken, []byte(content), 0o600))
	require.NoError(t, os.WriteFile(valid, []byte("header\n0: ignored 0200000A:0035\n"), 0o600))
	cidrs, warnings := readProcNetCIDRs([]string{broken, valid})
	assert.Equal(t, []string{"127.0.0.1/32", "10.0.0.2/32"}, cidrs)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], broken)
	assert.Contains(t, warnings[0], "scan")
}

func TestReadProcNetCIDRs_ReportsDirectoryReadError(t *testing.T) {
	path := t.TempDir()
	cidrs, warnings := readProcNetCIDRs([]string{path})
	assert.Empty(t, cidrs)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], path)
}
