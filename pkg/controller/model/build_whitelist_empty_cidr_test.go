package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_EmptyCIDRsProducesEmpty(t *testing.T) {
	snap := HostSnapshot{CIDRs: []string{}}
	w := BuildWhitelist(snap, time.Now())
	assert.Empty(t, w.Network.CIDRAllow)
}
