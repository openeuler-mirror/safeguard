package model

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestBuildWhitelistPreservesProcessNameSpaces(t *testing.T) {
	snapshot := HostSnapshot{RunningProcesses: []RunningProcess{
		{Command: "app"}, {Command: " app"}, {Executable: "/opt/app "},
	}}
	whitelist := BuildWhitelist(snapshot, time.Time{})
	require.Equal(t, []string{" app", "app", "app "}, whitelist.Process.Allow)
}

func TestBuildWhitelistPreservesFilePathSpaces(t *testing.T) {
	snapshot := HostSnapshot{
		Accounts:        []Account{{HomeDir: "/home/user "}, {HomeDir: "/home/user"}},
		ExecutablePaths: []string{"/opt/app ", "/opt/app", "/opt/app "},
	}
	whitelist := BuildWhitelist(snapshot, time.Time{})
	for _, path := range []string{"/home/user ", "/home/user", "/opt/app ", "/opt/app"} {
		require.Contains(t, whitelist.Files.Allow, path)
	}
	count := 0
	for _, path := range whitelist.Files.Allow {
		if path == "/opt/app " {
			count++
		}
	}
	require.Equal(t, 1, count)
}

func TestBuildWhitelistAccountsIndependent(t *testing.T) {
	snapshot := HostSnapshot{Accounts: []Account{{Username: "alice", HomeDir: "/home/alice"}, {Username: "bob", UID: 1001}}}
	whitelist := BuildWhitelist(snapshot, time.Time{})
	snapshot.Accounts[0].Username = "changed"
	assert.Equal(t, "alice", whitelist.Accounts[0].Username)
	whitelist.Accounts[1].UID = 42
	assert.Equal(t, uint(1001), snapshot.Accounts[1].UID)
	assert.Nil(t, BuildWhitelist(HostSnapshot{}, time.Time{}).Accounts)
	assert.NotNil(t, BuildWhitelist(HostSnapshot{Accounts: []Account{}}, time.Time{}).Accounts)
}

func TestBuildWhitelistCanonicalCIDR(t *testing.T) {
	cidrs := make([]string, 0, 260)
	for i := 0; i < 256; i++ {
		cidrs = append(cidrs, fmt.Sprintf("10.1.2.%d/24", i))
	}
	cidrs = append(cidrs, "2001:db8::1/64", "2001:db8::abcd/64", "invalid")
	whitelist, warnings := buildNetworkWhitelist(cidrs, nil, nil)
	assert.Equal(t, []string{"10.1.2.0/24", "2001:db8::/64", "invalid"}, whitelist.CIDRAllow)
	assert.Empty(t, warnings)
}

func TestBuildWhitelistProcessCollision(t *testing.T) {
	first := "long-process-name-alpha"
	second := "long-process-name-beta"
	snapshot := HostSnapshot{RunningProcesses: []RunningProcess{{Command: first}, {Command: second}, {Command: first}, {Command: "short"}}}
	whitelist := BuildWhitelist(snapshot, time.Time{})
	assert.Contains(t, whitelist.Process.Allow, "long-process-na")
	assert.Len(t, whitelist.Warnings, 1)
	if len(whitelist.Warnings) > 0 {
		assert.Contains(t, whitelist.Warnings[0], first)
		assert.Contains(t, whitelist.Warnings[0], second)
		assert.Contains(t, whitelist.Warnings[0], "long-process-na")
	}
}

func TestBuildWhitelistStableAccounts(t *testing.T) {
	a := Account{Username: "alice", UID: 2, GID: 3, HomeDir: "/home/a", Shell: "/bin/z"}
	b := Account{Username: "alice", UID: 2, GID: 3, HomeDir: "/home/a", Shell: "/bin/a"}
	c := Account{Username: "bob", UID: 1, GID: 1, HomeDir: "/home/b"}
	first := HostSnapshot{Accounts: []Account{c, a, b}}
	second := HostSnapshot{Accounts: []Account{b, c, a}}
	result := BuildWhitelist(first, time.Time{})
	assert.Equal(t, []Account{b, a, c}, result.Accounts)
	assert.Equal(t, result.Accounts, BuildWhitelist(second, time.Time{}).Accounts)
	assert.Equal(t, []Account{c, a, b}, first.Accounts)
}

func TestBuildWhitelistStableCollisions(t *testing.T) {
	a := RunningProcess{Command: "long-process-name-alpha"}
	b := RunningProcess{Command: "long-process-name-beta"}
	c := RunningProcess{Command: "long-process-name-gamma"}
	first := BuildWhitelist(HostSnapshot{RunningProcesses: []RunningProcess{a, b, c, a}}, time.Time{})
	second := BuildWhitelist(HostSnapshot{RunningProcesses: []RunningProcess{c, b, a}}, time.Time{})
	assert.Equal(t, first.Process.Allow, second.Process.Allow)
	assert.Equal(t, first.Warnings, second.Warnings)
	assert.Len(t, first.Warnings, 1)
	if len(first.Warnings) > 0 {
		for _, name := range []string{a.Command, b.Command, c.Command} {
			assert.Contains(t, first.Warnings[0], name)
		}
	}
}
