package model

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultFileAllow contains default allowed file paths
var defaultFileAllow = []string{
	"/", "/bin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/etc",
	"/tmp", "/var", "/run", "/usr/lib", "/home", "/root",
}

// BuildWhitelist creates a WhitelistModel from HostSnapshot
func BuildWhitelist(snapshot HostSnapshot, generatedAt time.Time) WhitelistModel {
	fileAllow := append([]string{}, defaultFileAllow...)
	fileAllow = append(fileAllow, snapshot.ExecutablePaths...)

	for _, account := range snapshot.Accounts {
		if account.HomeDir != "" {
			fileAllow = append(fileAllow, account.HomeDir)
		}
	}

	processAllow := make([]string, 0, len(snapshot.RunningProcesses))
	for _, process := range snapshot.RunningProcesses {
		if process.Command != "" {
			processAllow = append(processAllow, process.Command)
		}
		if process.Executable != "" {
			processAllow = append(processAllow, filepath.Base(process.Executable))
		}
	}

	// TODO: return WhitelistModel
	return WhitelistModel{}
}

// uniqueStrings removes duplicates and sorts string slices
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

// uniqueUints removes duplicates and sorts uint slices
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
