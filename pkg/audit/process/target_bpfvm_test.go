//go:build bpfvm
// +build bpfvm

package process

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestProcessContainerTargetVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires an isolated VM: attaches blocking LSM hooks")
	}
	conf := config.DefaultConfig()
	conf.Policy = "whitelist"
	conf.RestrictedProcessConfig.Enable = true
	conf.RestrictedProcessConfig.Mode = "block"
	conf.RestrictedProcessConfig.Target = "container"
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	require.NoError(t, exec.Command("/bin/probe").Run(), "host process should be allowed")
	cmd := exec.Command("/bin/probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	require.ErrorIs(t, cmd.Run(), syscall.EPERM, "new mount namespace should be restricted")
	conf.RestrictedProcessConfig.Target = "host"
	require.NoError(t, mgr.SetConfigToMap())
	require.ErrorIs(t, exec.Command("/bin/probe").Run(), syscall.EPERM, "host target should enforce")
}
