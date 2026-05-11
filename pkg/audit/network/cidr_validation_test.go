package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{"valid IPv4 CIDR", "192.168.1.0/24", true},
		{"valid IPv4 single", "10.0.0.1/32", true},
		{"valid IPv6 CIDR", "2001:db8::/32", true},
		{"invalid no prefix", "192.168.1.0", false},
		{"invalid bad IP", "256.1.1.1/24", false},
		{"invalid bad prefix", "192.168.1.0/33", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidCIDR(tt.cidr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateCIDRList(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		expected []string
	}{
		{"all valid", []string{"10.0.0.0/8", "192.168.0.0/16"}, nil},
		{"mixed", []string{"10.0.0.0/8", "invalid", "192.168.0.0/16"}, []string{"invalid"}},
		{"all invalid", []string{"bad", "worse"}, []string{"bad", "worse"}},
		{"empty", []string{}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCIDRList(tt.cidrs)
			assert.Equal(t, tt.expected, result)
		})
	}
}
