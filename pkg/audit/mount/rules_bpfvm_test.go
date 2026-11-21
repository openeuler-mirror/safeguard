//go:build bpfvm
// +build bpfvm

package mount

import (
	"context"
	"os"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestMountMultipleRulesVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	for _, path := range []string{"/tmp/sg-first", "/tmp/sg-second", "/tmp/sg-second-extra", "/tmp/sg-dest"} {
		require.NoError(t, os.MkdirAll(path, 0755))
	}
	conf := config.DefaultConfig()
	conf.RestrictedMountConfig.Enable = true
	conf.RestrictedMountConfig.Mode = "block"
	conf.RestrictedMountConfig.Target = "host"
	conf.RestrictedMountConfig.DenySourcePath = []string{"/tmp/sg-first", "/tmp/sg-second"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	for _, path := range conf.RestrictedMountConfig.DenySourcePath {
		err := syscall.Mount(path, "/tmp/sg-dest", "", syscall.MS_BIND, "")
		if err == nil {
			syscall.Unmount("/tmp/sg-dest", 0)
		}
		require.ErrorIs(t, err, syscall.EPERM, path)
	}
	require.NoError(t, syscall.Mount("/tmp/sg-second-extra", "/tmp/sg-dest", "", syscall.MS_BIND, ""))
	require.NoError(t, syscall.Unmount("/tmp/sg-dest", 0))
	conf.RestrictedMountConfig.DenySourcePath = []string{"/"}
	require.NoError(t, mgr.SetConfigToMap())
	err = syscall.Mount("/tmp/sg-second-extra", "/tmp/sg-dest", "", syscall.MS_BIND, "")
	if err == nil {
		syscall.Unmount("/tmp/sg-dest", 0)
	}
	require.ErrorIs(t, err, syscall.EPERM)
}
