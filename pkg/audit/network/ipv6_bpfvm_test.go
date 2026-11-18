//go:build bpfvm
// +build bpfvm

package network

import (
	"context"
	"os"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestIPv6CIDRDenyVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires an isolated VM: attaches blocking LSM hooks")
	}
	conf := config.DefaultConfig()
	conf.RestrictedNetworkConfig.Enable = true
	conf.RestrictedNetworkConfig.Mode = "block"
	conf.CIDR.Deny = []string{"::1/128", "127.0.0.2/32"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	for _, tc := range []struct {
		family int
		addr   syscall.Sockaddr
		want   error
	}{
		{syscall.AF_INET6, &syscall.SockaddrInet6{Port: 54321, Addr: [16]byte{15: 1}}, syscall.EPERM},
		{syscall.AF_INET, &syscall.SockaddrInet4{Port: 54321, Addr: [4]byte{127, 0, 0, 2}}, syscall.EPERM},
		{syscall.AF_INET, &syscall.SockaddrInet4{Port: 54321, Addr: [4]byte{127, 0, 0, 1}}, syscall.ECONNREFUSED},
	} {
		fd, err := syscall.Socket(tc.family, syscall.SOCK_STREAM, 0)
		require.NoError(t, err)
		err = syscall.Connect(fd, tc.addr)
		syscall.Close(fd)
		require.ErrorIs(t, err, tc.want, "%v", tc.addr)
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	err = syscall.Bind(fd, &syscall.SockaddrInet6{Port: 54322, Addr: [16]byte{15: 1}})
	syscall.Close(fd)
	require.ErrorIs(t, err, syscall.EPERM)
}
