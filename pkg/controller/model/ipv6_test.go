package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_IPv6OnlyCIDRs(t *testing.T) {
	whitelist := BuildWhitelist(HostSnapshot{
		CIDRs: []string{"2001:db8::/32", "fe80::/10"},
	}, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))

	assert.Contains(t, whitelist.Network.CIDRAllow, "2001:db8::/32")
	assert.Contains(t, whitelist.Network.CIDRAllow, "fe80::/10")
}
