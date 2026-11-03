package config

import (
	"fmt"
	"net"
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
