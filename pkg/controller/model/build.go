package model

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// bpfMapLimitEntries is the maximum number of entries in a BPF map.
// bpfProcessMapLimit is the maximum number of allowed process entries.
// bpfProcessNameMaxLength is the maximum length of a process name in a BPF map key.
const (
	bpfMapLimitEntries      = 256
	bpfProcessMapLimit      = 1024
	bpfProcessNameMaxLength = 15
)

// defaultFileAllow lists the default directory paths allowed for file access.
var defaultFileAllow = []string{
	"/bin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/etc",
	"/tmp", "/var", "/run", "/usr/lib", "/home", "/root",
}

// BuildWhitelist transforms a HostSnapshot into a WhitelistModel with deduplication and normalization.
func BuildWhitelist(snapshot HostSnapshot, generatedAt time.Time) WhitelistModel {
	fileAllow := append([]string{}, defaultFileAllow...)
	fileAllow = append(fileAllow, snapshot.ExecutablePaths...)
	processAllow := make([]string, 0, len(snapshot.RunningProcesses))
	warnings := append([]string{}, snapshot.Warnings...)
	var accounts []Account
	if snapshot.Accounts != nil {
		accounts = append([]Account{}, snapshot.Accounts...)
		sort.Slice(accounts, func(i, j int) bool {
			a, b := accounts[i], accounts[j]
			if a.Username != b.Username {
				return a.Username < b.Username
			}
			if a.UID != b.UID {
				return a.UID < b.UID
			}
			if a.GID != b.GID {
				return a.GID < b.GID
			}
			if a.HomeDir != b.HomeDir {
				return a.HomeDir < b.HomeDir
			}
			return a.Shell < b.Shell
		})
	}

	for _, account := range snapshot.Accounts {
		if account.HomeDir != "" {
			fileAllow = append(fileAllow, account.HomeDir)
		}
	}

	processNames := map[string]map[string]bool{}
	for _, process := range snapshot.RunningProcesses {
		name := processAllowName(process)
		if normalized := truncateString(name, bpfProcessNameMaxLength); normalized != "" {
			if processNames[normalized] == nil {
				processNames[normalized] = map[string]bool{}
			}
			processNames[normalized][name] = true
			processAllow = append(processAllow, normalized)
		}
	}
	for key, names := range processNames {
		if len(names) < 2 {
			continue
		}
		sorted := make([]string, 0, len(names))
		for name := range names {
			sorted = append(sorted, name)
		}
		sort.Strings(sorted)
		warnings = append(warnings, fmt.Sprintf("process names %q share truncated key %q", sorted, key))
	}

	networkWhitelist, networkWarnings := buildNetworkWhitelist(snapshot.CIDRs, snapshot.UIDs, snapshot.GIDs)
	fileAllow, fileAllowTruncated := clampStrings(uniqueFilePaths(fileAllow), bpfMapLimitEntries)
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
		Accounts: accounts,
		Files: FileWhitelist{
			Allow: fileAllow,
		},
		Process: ProcessWhitelist{
			Allow: processAllow,
		},
		Warnings: uniqueStrings(warnings),
	}
}

// buildNetworkWhitelist constructs the network whitelist from CIDRs, UIDs, and GIDs,
// clamping values to eBPF map limits and returning any truncation warnings.
func buildNetworkWhitelist(cidrs []string, uids []uint, gids []uint) (NetworkWhitelist, []string) {
	warnings := []string{}
	normalized := make([]string, 0, len(cidrs))
	for _, value := range cidrs {
		value = strings.TrimSpace(value)
		if _, prefix, err := net.ParseCIDR(value); err == nil {
			value = prefix.String()
		}
		normalized = append(normalized, value)
	}
	cidrAllow, cidrWarnings := clampCIDRs(uniqueStrings(normalized))
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

// clampCIDRs separates CIDRs into IPv4 and IPv6 groups, clamps each to the
// eBPF map limit, and returns the combined list with truncation warnings.
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

// normalizeProcessAllowEntry extracts the process name from a RunningProcess,
// preferring the executable basename over the command field, and truncates to
// the BPF process name length limit.
func normalizeProcessAllowEntry(process RunningProcess) string {
	return truncateString(processAllowName(process), bpfProcessNameMaxLength)
}

func processAllowName(process RunningProcess) string {
	candidate := strings.TrimSpace(process.Command)
	if process.Executable != "" {
		candidate = filepath.Base(process.Executable)
	}
	candidate = strings.TrimSpace(strings.TrimSuffix(candidate, " (deleted)"))
	return candidate
}

// truncateString truncates a string to at most maxLen bytes.
func truncateString(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen]
}

// clampStrings truncates a string slice to the given limit and reports whether
// truncation occurred.
func clampStrings(values []string, limit int) ([]string, bool) {
	if len(values) <= limit {
		return values, false
	}
	return values[:limit], true
}

// clampUints truncates a uint slice to the given limit and reports whether
// truncation occurred.
func clampUints(values []uint, limit int) ([]uint, bool) {
	if len(values) <= limit {
		return values, false
	}
	return values[:limit], true
}

// uniqueFilePaths preserves whitespace, which is significant in filenames.
func uniqueFilePaths(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

// uniqueStrings deduplicates and sorts a string slice, trimming whitespace and
// skipping empty entries.
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

// uniqueUints deduplicates and sorts a uint slice.
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
