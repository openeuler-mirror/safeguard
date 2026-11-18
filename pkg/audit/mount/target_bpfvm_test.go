//go:build bpfvm
// +build bpfvm

package mount

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestMountContainerTargetVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	require.NoError(t, os.MkdirAll("/tmp/sg-mount", 0755))
	mount := func(want error) {
		err := syscall.Mount("/bin", "/tmp/sg-mount", "", syscall.MS_BIND, "")
		if want == nil {
			require.NoError(t, err)
			require.NoError(t, syscall.Unmount("/tmp/sg-mount", 0))
		} else {
			require.ErrorIs(t, err, want)
		}
	}
	if os.Getenv("SAFEGUARD_MOUNT_TARGET_CHILD") == "1" {
		mount(syscall.EPERM)
		return
	}
	conf := config.DefaultConfig()
	conf.RestrictedMountConfig.Enable = true
	conf.RestrictedMountConfig.Mode = "block"
	conf.RestrictedMountConfig.Target = "container"
	conf.RestrictedMountConfig.DenySourcePath = []string{"/bin"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	mount(nil)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMountContainerTargetVM$")
	cmd.Env = append(os.Environ(), "SAFEGUARD_MOUNT_TARGET_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
