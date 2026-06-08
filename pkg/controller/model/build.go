package model

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	bpfMapLimitEntries      = 256
	bpfProcessMapLimit      = 1024
	bpfProcessNameMaxLength = 15
)

var defaultFileAllow = []string{
	"/bin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/etc",
	"/tmp", "/var", "/run", "/usr/lib", "/home", "/root",
}

func BuildWhitelist(snapshot HostSnapshot, generatedAt time.Time) WhitelistModel {
	fileAllow := append([]string{}, defaultFileAllow...)
	fileAllow = append(fileAllow, snapshot.ExecutablePaths...)
	processAllow := make([]string, 0, len(snapshot.RunningProcesses))
	warnings := append([]string{}, snapshot.Warnings...)

	for _, account := range snapshot.Accounts {
		if account.HomeDir != "" {
			fileAllow = append(fileAllow, account.HomeDir)
		}
	}

	for _, process := range snapshot.RunningProcesses {
		if normalized := normalizeProcessAllowEntry(process); normalized != "" {
			processAllow = append(processAllow, normalized)
		}
	}

	networkWhitelist, networkWarnings := buildNetworkWhitelist(snapshot.CIDRs, snapshot.UIDs, snapshot.GIDs)
	fileAllow, fileAllowTruncated := clampStrings(uniqueStrings(fileAllow), bpfMapLimitEntries)
	if fileAllowTruncated {
		warnings = append(warnings, fmt.Sprintf("generated files.allow truncated to %d entries to fit eBPF map limits", bpfMapLimitEntries))
	}

	processAllow, processAllowTruncated := clampStrings(uniqueStrings(processAllow), bpfProcessMapLimit)
	if processAllowTruncated {
		warnings = append(warnings, fmt.Sprintf("generated process.allow truncated to %d entries to fit eBPF map limits", bpfProcessMapLimit))
	}
	warnings = append(warnings, networkWarnings...)

	return WhitelistModel{
		Metadata: Metadata{
			Hostname:    snapshot.Hostname,
			GeneratedAt: generatedAt,
		},
		Network:  networkWhitelist,
		Accounts: snapshot.Accounts,
		Files: FileWhitelist{
			Allow: fileAllow,
		},
		Process: ProcessWhitelist{
			Allow: processAllow,
		},
		Warnings: uniqueStrings(warnings),
	}
}

func buildNetworkWhitelist(cidrs []string, uids []uint, gids []uint) (NetworkWhitelist, []string) {
	warnings := []string{}
	cidrAllow, cidrWarnings := clampCIDRs(uniqueStrings(cidrs))
	warnings = append(warnings, cidrWarnings...)

	uidAllow, uidTruncated := clampUints(uniqueUints(uids), bpfMapLimitEntries)
	if uidTruncated {
		warnings = append(warnings, fmt.Sprintf("generated network.uid.allow truncated to %d entries to fit eBPF map limits", bpfMapLimitEntries))
	}

	gidAllow, gidTruncated := clampUints(uniqueUints(gids), bpfMapLimitEntries)
	if gidTruncated {
		warnings = append(warnings, fmt.Sprintf("generated network.gid.allow truncated to %d entries to fit eBPF map limits", bpfMapLimitEntries))
	}

	return NetworkWhitelist{
		CIDRAllow: cidrAllow,
		UIDAllow:  uidAllow,
		GIDAllow:  gidAllow,
	}, warnings
}

func clampCIDRs(values []string) ([]string, []string) {
	ipv4 := make([]string, 0, len(values))
	ipv6 := make([]string, 0, len(values))
	unknown := make([]string, 0)

	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			unknown = append(unknown, value)
			continue
		}
		if network.IP.To4() != nil {
			ipv4 = append(ipv4, value)
			continue
		}
		ipv6 = append(ipv6, value)
	}

	warnings := []string{}
	var truncated bool

	ipv4, truncated = clampStrings(ipv4, bpfMapLimitEntries)
	if truncated {
		warnings = append(warnings, fmt.Sprintf("generated network.cidr.allow truncated to %d IPv4 entries to fit eBPF map limits", bpfMapLimitEntries))
	}

	ipv6, truncated = clampStrings(ipv6, bpfMapLimitEntries)
	if truncated {
		warnings = append(warnings, fmt.Sprintf("generated network.cidr.allow truncated to %d IPv6 entries to fit eBPF map limits", bpfMapLimitEntries))
	}

	result := append(ipv4, ipv6...)
	result = append(result, unknown...)
	return result, warnings
}

func normalizeProcessAllowEntry(process RunningProcess) string {
	candidate := strings.TrimSpace(process.Command)
	if process.Executable != "" {
		candidate = filepath.Base(process.Executable)
	}
	candidate = strings.TrimSpace(strings.TrimSuffix(candidate, " (deleted)"))
	if candidate == "" {
		return ""
	}

	return truncateString(candidate, bpfProcessNameMaxLength)
}

func truncateString(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen]
}

func clampStrings(values []string, limit int) ([]string, bool) {
	if len(values) <= limit {
		return values, false
	}
	return values[:limit], true
}

func clampUints(values []uint, limit int) ([]uint, bool) {
	if len(values) <= limit {
		return values, false
	}
	return values[:limit], true
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func uniqueUints(values []uint) []uint {
	seen := map[uint]struct{}{}
	result := make([]uint, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
