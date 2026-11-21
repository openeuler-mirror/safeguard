//go:build bpfvm
// +build bpfvm

package fileaccess

import (
	"context"
	"os"
	"syscall"
	"testing"

	"culinux/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestLegacyFileDenyVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	for _, path := range []string{"/tmp/sg-first", "/tmp/sg-second", "/tmp/sg-allowed"} {
		require.NoError(t, os.WriteFile(path, []byte("test"), 0600))
	}
	conf := config.DefaultConfig()
	conf.RestrictedFileAccessConfig.Enable = true
	conf.RestrictedFileAccessConfig.Mode = "block"
	conf.RestrictedFileAccessConfig.Target = "host"
	conf.RestrictedFileAccessConfig.Deny = []string{"|/tmp/sg-first|/tmp/sg-second"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	defer mgr.Close()
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	for _, path := range []string{"/tmp/sg-first", "/tmp/sg-second"} {
		f, err := os.Open(path)
		if f != nil {
			f.Close()
		}
		require.ErrorIs(t, err, syscall.EPERM, path)
	}
	f, err := os.Open("/tmp/sg-allowed")
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
