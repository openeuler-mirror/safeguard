package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadProcProcesses_SkipsNonNumericDirs(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "abc"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "101"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "101", "comm"), []byte("bash\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "101", "status"), []byte("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"), 0o644))

	processes, _, _, _, err := readProcProcesses(root)
	require.NoError(t, err)
	assert.Len(t, processes, 1)
	assert.Equal(t, "bash", processes[0].Command)
}

func TestReadProcProcesses_SkipsMissingCommFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "102"), 0o755))

	processes, _, _, _, err := readProcProcesses(root)
	require.NoError(t, err)
	assert.Empty(t, processes)
}
