package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_UIDAllowFromAccounts(t *testing.T) {
	snap := HostSnapshot{
		UIDs: []uint{0, 1000},
	}
	w := BuildWhitelist(snap, time.Now())
	assert.Contains(t, w.Network.UIDAllow, uint(0))
	assert.Contains(t, w.Network.UIDAllow, uint(1000))
}
