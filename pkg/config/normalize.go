package config

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// NormalizeCIDRs masks host bits, canonicalizes both address families and
// removes equivalent prefixes without modifying the input or its order.
func NormalizeCIDRs(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for i, value := range values {
		_, prefix, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		canonical := prefix.String()
		if !seen[canonical] {
			seen[canonical] = true
			normalized = append(normalized, canonical)
		}
	}
	return normalized, nil
}

// NormalizeIDs sorts unique IDs in a copy, leaving the caller's slice untouched.
func NormalizeIDs(values []uint) []uint {
	sorted := append([]uint{}, values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	result := sorted[:0]
	for _, value := range sorted {
		if len(result) == 0 || value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

// NormalizeDomains uses case-insensitive, absolute DNS names for exact matching.
func NormalizeDomains(values []string) []string {
	names := make([]string, len(values))
	for i, value := range values {
		names[i] = strings.ToLower(dns.Fqdn(value))
	}
	return UniqueStrings(names)
}
