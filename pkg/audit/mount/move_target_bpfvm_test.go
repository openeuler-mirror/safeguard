//go:build bpfvm
// +build bpfvm

package mount

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"unsafe"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMoveMountContainerTargetVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	require.NoError(t, os.MkdirAll("/tmp/sg-move", 0755))
	move := func(want error) {
		src, _ := syscall.BytePtrFromString("/tmp/sg-source")
		empty, _ := syscall.BytePtrFromString("")
		dst, _ := syscall.BytePtrFromString("/tmp/sg-move")
		atFDCWD := ^uintptr(99)
		fd, _, errno := syscall.Syscall(unix.SYS_OPEN_TREE, atFDCWD, uintptr(unsafe.Pointer(src)), 1|syscall.O_CLOEXEC)
		require.Zero(t, errno)
		_, _, errno = syscall.Syscall6(unix.SYS_MOVE_MOUNT, fd, uintptr(unsafe.Pointer(empty)), atFDCWD, uintptr(unsafe.Pointer(dst)), 4, 0)
		syscall.Close(int(fd))
		if want == nil {
			require.Zero(t, errno)
			require.NoError(t, syscall.Unmount("/tmp/sg-move", 0))
		} else {
			require.ErrorIs(t, errno, want)
		}
	}
	if os.Getenv("SAFEGUARD_MOVE_TARGET_CHILD") == "1" {
		move(syscall.EPERM)
		return
	}
	require.NoError(t, os.MkdirAll("/tmp/sg-source", 0755))
	require.NoError(t, syscall.Mount("safeguard-test", "/tmp/sg-source", "tmpfs", 0, ""))
	defer syscall.Unmount("/tmp/sg-source", 0)
	move(nil)
	conf := config.DefaultConfig()
	conf.RestrictedMountConfig.Enable = true
	conf.RestrictedMountConfig.Mode = "block"
	conf.RestrictedMountConfig.Target = "container"
	conf.RestrictedMountConfig.DenySourcePath = []string{"safeguard-test"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	move(nil)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMoveMountContainerTargetVM$")
	cmd.Env = append(os.Environ(), "SAFEGUARD_MOVE_TARGET_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
