//go:build bpfvm
// +build bpfvm

package fileaccess

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestFileContainerTargetVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	const path = "/tmp/sg-secret"
	open := func(want error) {
		f, err := os.Open(path)
		if want == nil {
			require.NoError(t, err)
			require.NoError(t, f.Close())
		} else {
			require.ErrorIs(t, err, want)
		}
	}
	if os.Getenv("SAFEGUARD_FILE_TARGET_CHILD") == "1" {
		open(syscall.EPERM)
		require.ErrorIs(t, os.Remove(path), syscall.EPERM)
		return
	}
	require.NoError(t, os.WriteFile(path, []byte("test"), 0600))
	conf := config.DefaultConfig()
	conf.RestrictedFileAccessConfig.Enable = true
	conf.RestrictedFileAccessConfig.Mode = "block"
	conf.RestrictedFileAccessConfig.Target = "container"
	conf.RestrictedFileAccessConfig.Deny = []string{path}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	defer mgr.Close()
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	open(nil)
	cmd := exec.Command(os.Args[0], "-test.run=^TestFileContainerTargetVM$")
	cmd.Env = append(os.Environ(), "SAFEGUARD_FILE_TARGET_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
