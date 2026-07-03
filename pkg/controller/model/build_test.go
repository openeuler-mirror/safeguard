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

func TestBuildNetworkWhitelist_NormalizesCIDRsAndIDs(t *testing.T) {
	whitelist, warnings := buildNetworkWhitelist(
		[]string{
			"2001:db8::8/128",
			"10.0.0.8/32",
			"not-a-cidr",
			"10.0.0.8/32",
			"2001:db8::8/128",
		},
		[]uint{5, 1, 5},
		[]uint{9, 3, 9},
	)

	assert.Equal(t, []string{"10.0.0.8/32", "2001:db8::8/128", "not-a-cidr"}, whitelist.CIDRAllow)
	assert.Equal(t, []uint{1, 5}, whitelist.UIDAllow)
	assert.Equal(t, []uint{3, 9}, whitelist.GIDAllow)
	assert.Empty(t, warnings)
}

func TestBuildNetworkWhitelist_PreservesInvalidCIDRsAfterTruncatedFamilies(t *testing.T) {
	cidrs := make([]string, 0, 520)
	for i := 0; i < 260; i++ {
		cidrs = append(cidrs, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256))
	}
	for i := 0; i < 260; i++ {
		cidrs = append(cidrs, fmt.Sprintf("2001:db8::%x/128", i))
	}
	cidrs = append(cidrs, "still-invalid")

	whitelist, warnings := buildNetworkWhitelist(cidrs, nil, nil)

	assert.Len(t, whitelist.CIDRAllow, 513)
	assert.Equal(t, "10.0.0.0/32", whitelist.CIDRAllow[0])
	assert.Equal(t, "still-invalid", whitelist.CIDRAllow[len(whitelist.CIDRAllow)-1])
	assert.Contains(t, warnings, "generated network.cidr.allow truncated to 256 IPv4 entries to fit eBPF map limits")
	assert.Contains(t, warnings, "generated network.cidr.allow truncated to 256 IPv6 entries to fit eBPF map limits")
}
