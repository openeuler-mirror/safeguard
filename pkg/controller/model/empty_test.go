package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_EmptySnapshotProducesDefaults(t *testing.T) {
	whitelist := BuildWhitelist(HostSnapshot{}, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, "", whitelist.Metadata.Hostname)
	assert.Empty(t, whitelist.Network.CIDRAllow)
	assert.Empty(t, whitelist.Network.UIDAllow)
	assert.Empty(t, whitelist.Network.GIDAllow)
	assert.Empty(t, whitelist.Accounts)
	assert.Contains(t, whitelist.Files.Allow, "/bin")
	assert.Contains(t, whitelist.Files.Allow, "/usr/bin")
	assert.Empty(t, whitelist.Process.Allow)
	assert.Empty(t, whitelist.Warnings)
}
