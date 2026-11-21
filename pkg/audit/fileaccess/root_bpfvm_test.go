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

func TestRootFileRuleVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	for _, path := range []string{"/tmp/sg-root-allowed", "/tmp/sg-root-denied"} {
		require.NoError(t, os.WriteFile(path, []byte("test"), 0600))
	}
	conf := config.DefaultConfig()
	conf.Policy = "whitelist"
	conf.RestrictedFileAccessConfig.Enable = true
	conf.RestrictedFileAccessConfig.Mode = "block"
	conf.RestrictedFileAccessConfig.Target = "host"
	conf.RestrictedFileAccessConfig.Allow = []string{"/"}
	conf.RestrictedFileAccessConfig.Deny = []string{"/tmp/sg-root-denied"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	defer mgr.Close()
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	f, err := os.Open("/tmp/sg-root-allowed")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	f, err = os.Open("/tmp/sg-root-denied")
	if f != nil {
		f.Close()
	}
	require.ErrorIs(t, err, syscall.EPERM)
}
