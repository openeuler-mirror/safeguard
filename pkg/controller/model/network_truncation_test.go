package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildNetworkWhitelist_LargeUIDListTruncated(t *testing.T) {
	uids := make([]uint, 300)
	for i := range uids { uids[i] = uint(i) }
	wl, warnings := buildNetworkWhitelist(nil, uids, nil)
	assert.LessOrEqual(t, len(wl.UIDAllow), 256)
	assert.NotEmpty(t, warnings)
}
