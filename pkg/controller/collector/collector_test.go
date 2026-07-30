package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotCollector_CollectsAndMergesHostData(t *testing.T) {
	root := t.TempDir()
	passwdPath := filepath.Join(root, "passwd")
	procRoot := filepath.Join(root, "proc")
	netRoot := filepath.Join(root, "net")

	require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "101"), 0o755))
	require.NoError(t, os.MkdirAll(netRoot, 0o755))

	require.NoError(t, os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(procRoot, "101", "comm"), []byte("bash\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(procRoot, "101", "status"), []byte("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(netRoot, "tcp"), []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 0200000A:1F90 01 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0\n"), 0o644))

	require.NoError(t, os.Symlink("/usr/bin/bash", filepath.Join(procRoot, "101", "exe")))

	collector := SnapshotCollector{
		PasswdPath:   passwdPath,
		ProcRoot:     procRoot,
		ProcNetPaths: []string{filepath.Join(netRoot, "tcp")},
		HostnameFn: func() (string, error) {
			return "demo-host", nil
		},
		InterfaceCIDRsFn: func() ([]string, error) {
			return []string{"192.168.0.10/24"}, nil
		},
	}

	snapshot, err := collector.Collect()
	require.NoError(t, err)
	assert.Equal(t, "demo-host", snapshot.Hostname)
	assert.Contains(t, snapshot.CIDRs, "10.0.0.2/32")
	assert.Contains(t, snapshot.CIDRs, "192.168.0.10/24")
	assert.Contains(t, snapshot.UIDs, uint(0))
	assert.Contains(t, snapshot.GIDs, uint(0))
	assert.Len(t, snapshot.Accounts, 1)
	assert.Len(t, snapshot.RunningProcesses, 1)
	assert.Equal(t, []string{"/usr/bin/bash"}, snapshot.ExecutablePaths)
}

func TestSnapshotCollector_StoresWarningsForUnreadableProcNetFiles(t *testing.T) {
	root := t.TempDir()
	passwdPath := filepath.Join(root, "passwd")
	procRoot := filepath.Join(root, "proc")

	require.NoError(t, os.MkdirAll(procRoot, 0o755))
	require.NoError(t, os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644))

	collector := SnapshotCollector{
		PasswdPath:   passwdPath,
		ProcRoot:     procRoot,
		ProcNetPaths: []string{filepath.Join(root, "missing-tcp")},
		HostnameFn: func() (string, error) {
			return "demo-host", nil
		},
		InterfaceCIDRsFn: func() ([]string, error) {
			return []string{"127.0.0.1/8"}, nil
		},
	}

	snapshot, err := collector.Collect()
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1/8"}, snapshot.CIDRs)
	assert.Len(t, snapshot.Warnings, 1)
}

func TestReadPasswdAccounts_SkipsMalformedLines(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "passwd")
	content := "root:x:0:0:root:/root:/bin/bash\nshortline\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	accounts, uids, gids, err := readPasswdAccounts(path)
	require.NoError(t, err)
	assert.Len(t, accounts, 2)
	assert.Contains(t, uids, uint(0))
	assert.Contains(t, gids, uint(65534))
}

func TestReadPasswdAccounts_SkipsNonNumericUID(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "passwd")
	content := "baduser:x:abc:0:baduser:/home:/bin/bash\nroot:x:0:0:root:/root:/bin/bash\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	accounts, uids, _, err := readPasswdAccounts(path)
	require.NoError(t, err)
	assert.Len(t, accounts, 1)
	assert.Contains(t, uids, uint(0))
}

func TestReadPasswdAccounts_ReturnsErrorForMissingFile(t *testing.T) {
	_, _, _, err := readPasswdAccounts("/nonexistent/passwd")
	assert.Error(t, err)
}

func TestParseStatusIDs(t *testing.T) {
	uid, gid := parseStatusIDs("Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	assert.Equal(t, uint(1000), uid)
	assert.Equal(t, uint(1000), gid)
}

func TestParseStatusIDs_ReturnsZeroForMissingFields(t *testing.T) {
	uid, gid := parseStatusIDs("Name:\tbash\n")
	assert.Equal(t, uint(0), uid)
	assert.Equal(t, uint(0), gid)
}
