package model

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var defaultFileAllow = []string{
	"/", "/bin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/etc",
	"/tmp", "/var", "/run", "/usr/lib", "/home", "/root",
}

func BuildWhitelist(snapshot HostSnapshot, generatedAt time.Time) WhitelistModel {
	fileAllow := append([]string{}, defaultFileAllow...)
	fileAllow = append(fileAllow, snapshot.ExecutablePaths...)
	processAllow := make([]string, 0, len(snapshot.RunningProcesses))

	for _, account := range snapshot.Accounts {
		if account.HomeDir != "" {
			fileAllow = append(fileAllow, account.HomeDir)
		}
	}

	for _, process := range snapshot.RunningProcesses {
		if process.Command != "" {
			processAllow = append(processAllow, process.Command)
		}
		if process.Executable != "" {
			processAllow = append(processAllow, filepath.Base(process.Executable))
		}
	}

	return WhitelistModel{
		Metadata: Metadata{
			Hostname:    snapshot.Hostname,
			GeneratedAt: generatedAt,
		},
		Network: NetworkWhitelist{
			CIDRAllow: uniqueStrings(snapshot.CIDRs),
			UIDAllow:  uniqueUints(snapshot.UIDs),
			GIDAllow:  uniqueUints(snapshot.GIDs),
		},
		Accounts: snapshot.Accounts,
		Files: FileWhitelist{
			Allow: uniqueStrings(fileAllow),
		},
		Process: ProcessWhitelist{
			Allow: uniqueStrings(processAllow),
		},
		Warnings: uniqueStrings(snapshot.Warnings),
	}
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
