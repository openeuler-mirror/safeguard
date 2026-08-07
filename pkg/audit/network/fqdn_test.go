package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_toFqdn(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		expect string
	}{
		{
			name:   "example.com -> example.com.",
			domain: "example.com",
			expect: "example.com.",
		},
		{
			name:   "example.com. -> example.com.",
			domain: "example.com.",
			expect: "example.com.",
		},
		{
			// Audit #18: empty string used to panic at
			// domainName[len(domainName)-1:]. Lock in the
			// defensive behavior so the regression cannot silently
			// reappear if the guard is ever refactored away.
			name:   "empty -> empty (no panic)",
			domain: "",
			expect: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expect, toFqdn(test.domain))
		})
	}
}
