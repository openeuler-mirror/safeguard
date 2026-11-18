//go:build bpfvm
// +build bpfvm

package network

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestNetworkContainerTargetVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	connect := func(want error) {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		require.NoError(t, err)
		err = syscall.Connect(fd, &syscall.SockaddrInet6{Port: 54321, Addr: [16]byte{15: 1}})
		syscall.Close(fd)
		require.ErrorIs(t, err, want)
	}
	if os.Getenv("SAFEGUARD_NETWORK_TARGET_CHILD") == "1" {
		connect(syscall.EPERM)
		return
	}
	conf := config.DefaultConfig()
	conf.RestrictedNetworkConfig.Enable = true
	conf.RestrictedNetworkConfig.Mode = "block"
	conf.RestrictedNetworkConfig.Target = "container"
	conf.CIDR.Deny = []string{"::1/128"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	connect(syscall.ECONNREFUSED)
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetworkContainerTargetVM$")
	cmd.Env = append(os.Environ(), "SAFEGUARD_NETWORK_TARGET_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
