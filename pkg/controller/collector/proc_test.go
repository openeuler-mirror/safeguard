package collector

import (
	"fmt"
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

func TestReadProcProcessesInvalidIdentity(t *testing.T) {
	root := t.TempDir()
	statuses := []string{
		"Uid: 0\nGid: 0\n", "Uid: 4294967295\nGid: 1\n",
		"Name: test\n", "Uid: bad\nGid: 2\n", "Uid: 3\nGid: 4294967296\n",
		"Uid: 4\nUid: 5\nGid: 6\n", "Uid: 4294967296\nGid: 0\n",
	}
	for i, status := range statuses {
		dir := filepath.Join(root, fmt.Sprint(i+1))
		require.NoError(t, os.Mkdir(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte("app\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0644))
	}
	processes, uids, gids, _, err := readProcProcesses(root)
	require.NoError(t, err)
	require.Len(t, processes, 2)
	require.Equal(t, []uint{0, 4294967295}, uids)
	require.Equal(t, []uint{0, 1}, gids)
}

func TestReadProcProcessesPIDRange(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"0", "+1", "-1", "01", "4194304", "999999999999999999999", "1", "4194303"} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte("app\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte("Uid: 1\nGid: 2\n"), 0644))
	}
	processes, _, _, _, err := readProcProcesses(root)
	require.NoError(t, err)
	require.Len(t, processes, 2)
	require.Equal(t, 1, processes[0].PID)
	require.Equal(t, 4194303, processes[1].PID)
}

func TestReadProcProcessesDeletedExecutable(t *testing.T) {
	root := t.TempDir()
	for i, target := range []string{"/usr/bin/old (deleted)", "/usr/bin/live"} {
		dir := filepath.Join(root, fmt.Sprint(i+1))
		require.NoError(t, os.Mkdir(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte("app\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte("Uid: 1\nGid: 2\n"), 0644))
		require.NoError(t, os.Symlink(target, filepath.Join(dir, "exe")))
	}
	processes, _, _, paths, err := readProcProcesses(root)
	require.NoError(t, err)
	require.Len(t, processes, 2)
	require.Empty(t, processes[0].Executable)
	require.Equal(t, "app", processes[0].Command)
	require.Equal(t, []string{"/usr/bin/live"}, paths)
}

func TestReadProcProcessesCommandWhitespace(t *testing.T) {
	root := t.TempDir()
	commands := []string{" app \n", "\tworker\t\n", "no-newline"}
	expected := []string{" app ", "\tworker\t", "no-newline"}
	for i, command := range commands {
		dir := filepath.Join(root, fmt.Sprint(i+1))
		require.NoError(t, os.Mkdir(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(command), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte("Uid: 1\nGid: 2\n"), 0644))
	}
	processes, _, _, _, err := readProcProcesses(root)
	require.NoError(t, err)
	require.Len(t, processes, len(expected))
	for i, want := range expected {
		require.Equal(t, want, processes[i].Command)
	}
}
