package render

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"culinux/pkg/config"
	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildWhitelist_DeduplicatesAndPopulatesFields(t *testing.T) {
	snapshot := model.HostSnapshot{
		Hostname: "demo-host",
		CIDRs:    []string{"10.0.0.1/32", "10.0.0.1/32"},
		Accounts: []model.Account{
			{Username: "root", UID: 0, GID: 0, HomeDir: "/root", Shell: "/bin/bash"},
		},
		UIDs: []uint{0, 0},
		GIDs: []uint{0, 0},
		RunningProcesses: []model.RunningProcess{
			{PID: 1, Command: "systemd", Executable: "/usr/lib/systemd/systemd", UID: 0, GID: 0},
		},
		ExecutablePaths: []string{"/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd"},
		Warnings:        []string{"proc/net/tcp unreadable", "proc/net/tcp unreadable"},
	}

	whitelist := model.BuildWhitelist(snapshot, time.Date(2026, 4, 13, 9, 0, 0, 0, time.UTC))

	assert.Equal(t, []string{"10.0.0.1/32"}, whitelist.Network.CIDRAllow)
	assert.Equal(t, []uint{0}, whitelist.Network.UIDAllow)
	assert.Equal(t, []uint{0}, whitelist.Network.GIDAllow)
	assert.NotContains(t, whitelist.Files.Allow, "/")
	assert.Contains(t, whitelist.Files.Allow, "/root")
	assert.Contains(t, whitelist.Files.Allow, "/usr/lib/systemd/systemd")
	assert.Equal(t, []string{"systemd"}, whitelist.Process.Allow)
	assert.Equal(t, []string{"proc/net/tcp unreadable"}, whitelist.Warnings)
}

func TestMarshalConfigYAML_RoundTripsThroughConfigParser(t *testing.T) {
	whitelist := model.WhitelistModel{
		Metadata: model.Metadata{
			Hostname:    "demo-host",
			GeneratedAt: time.Date(2026, 4, 13, 9, 0, 0, 0, time.UTC),
		},
		Network: model.NetworkWhitelist{
			CIDRAllow: []string{"127.0.0.1/32"},
			UIDAllow:  []uint{0},
			GIDAllow:  []uint{0},
		},
		Accounts: []model.Account{
			{Username: "root", UID: 0, GID: 0, HomeDir: "/root", Shell: "/bin/bash"},
		},
		Files: model.FileWhitelist{
			Allow: []string{"/", "/root"},
		},
		Process: model.ProcessWhitelist{
			Allow: []string{"bash"},
		},
	}

	data, err := MarshalConfigYAML(whitelist, "monitor")
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.yaml")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	cfg, err := config.NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1/32"}, cfg.RestrictedNetworkConfig.CIDR.Allow)
	assert.Equal(t, []string{"/", "/root"}, cfg.RestrictedFileAccessConfig.Allow)
	assert.Equal(t, []string{"bash"}, cfg.RestrictedProcessConfig.Allow)
}

func TestBuildConfig_UsesRequestedModeForAllModules(t *testing.T) {
	cfg := BuildConfig(model.WhitelistModel{}, "block")

	assert.Equal(t, "block", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedProcessConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedMountConfig.Mode)
}
