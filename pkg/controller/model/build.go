package model

import (
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
	// TODO: implement
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
