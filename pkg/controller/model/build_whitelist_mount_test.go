package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_WarningsFromSnapshot(t *testing.T) {
	snap := HostSnapshot{
		Warnings: []string{"test warning"},
	}
	w := BuildWhitelist(snap, time.Now())
	assert.Contains(t, w.Warnings, "test warning")
}
