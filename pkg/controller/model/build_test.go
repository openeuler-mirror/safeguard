package model

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_NormalizesProcessNamesForBPFMatching(t *testing.T) {
	snapshot := HostSnapshot{
		RunningProcesses: []RunningProcess{
			{
				Command:    "at-spi-bus-laun",
				Executable: "/usr/libexec/at-spi-bus-launcher",
			},
			{
				Command:    "at-spi-bus-launcher",
				Executable: "/usr/libexec/at-spi-bus-launcher",
			},
			{
				Command: "bash",
			},
		},
	}

	whitelist := BuildWhitelist(snapshot, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, []string{"at-spi-bus-laun", "bash"}, whitelist.Process.Allow)
}

func TestBuildWhitelist_ClampsListsToEBPFMapCapacities(t *testing.T) {
	cidrs := make([]string, 0, 300)
	uids := make([]uint, 0, 300)
	gids := make([]uint, 0, 300)
	executablePaths := make([]string, 0, 300)
	processes := make([]RunningProcess, 0, 1100)

	for i := 0; i < 300; i++ {
		cidrs = append(cidrs, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256))
		uids = append(uids, uint(i))
		gids = append(gids, uint(i))
		executablePaths = append(executablePaths, fmt.Sprintf("/opt/demo/bin/tool-%03d", i))
	}

	for i := 0; i < 1100; i++ {
		processes = append(processes, RunningProcess{
			Executable: fmt.Sprintf("/usr/bin/proc-%04d", i),
		})
	}

	whitelist := BuildWhitelist(HostSnapshot{
		CIDRs:            cidrs,
		UIDs:             uids,
		GIDs:             gids,
		ExecutablePaths:  executablePaths,
		RunningProcesses: processes,
	}, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))

	assert.Len(t, whitelist.Network.CIDRAllow, 256)
	assert.Len(t, whitelist.Network.UIDAllow, 256)
	assert.Len(t, whitelist.Network.GIDAllow, 256)
	assert.Len(t, whitelist.Files.Allow, 256)
	assert.Len(t, whitelist.Process.Allow, 1024)
	assert.Contains(t, whitelist.Warnings, "generated network.cidr.allow truncated to 256 IPv4 entries to fit eBPF map limits")
	assert.Contains(t, whitelist.Warnings, "generated network.uid.allow truncated to 256 entries to fit eBPF map limits")
	assert.Contains(t, whitelist.Warnings, "generated network.gid.allow truncated to 256 entries to fit eBPF map limits")
	assert.Contains(t, whitelist.Warnings, "generated files.allow truncated to 256 entries to fit eBPF map limits")
	assert.Contains(t, whitelist.Warnings, "generated process.allow truncated to 1024 entries to fit eBPF map limits")
}
