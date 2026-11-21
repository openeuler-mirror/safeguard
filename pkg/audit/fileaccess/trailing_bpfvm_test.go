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

func TestTrailingFileRulesVM(t *testing.T) {
	if os.Getenv("SAFEGUARD_ISOLATED_BPF_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	require.NoError(t, os.MkdirAll("/tmp/sg-dir/blocked", 0755))
	for _, path := range []string{"/tmp/sg-dir/allowed", "/tmp/sg-dir/blocked/file"} {
		require.NoError(t, os.WriteFile(path, []byte("test"), 0600))
	}
	conf := config.DefaultConfig()
	conf.Policy = "whitelist"
	conf.RestrictedFileAccessConfig.Enable = true
	conf.RestrictedFileAccessConfig.Mode = "block"
	conf.RestrictedFileAccessConfig.Target = "host"
	conf.RestrictedFileAccessConfig.Allow = []string{"/tmp/sg-dir/"}
	conf.RestrictedFileAccessConfig.Deny = []string{"/tmp/sg-dir/blocked/"}
	mod, err := setupBPFProgram(context.Background())
	require.NoError(t, err)
	defer mod.Close()
	mgr := &Manager{mod: mod, config: conf}
	defer mgr.Close()
	require.NoError(t, mgr.SetConfigToMap())
	require.NoError(t, mgr.Attach())
	f, err := os.Open("/tmp/sg-dir/allowed")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	f, err = os.Open("/tmp/sg-dir/blocked/file")
	if f != nil {
		f.Close()
	}
	require.ErrorIs(t, err, syscall.EPERM)
}
