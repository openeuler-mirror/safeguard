package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_FileAllowIncludesHomeDirs(t *testing.T) {
	snap := HostSnapshot{
		Accounts: []Account{{Username: "root", UID: 0, GID: 0, HomeDir: "/root"}},
	}
	w := BuildWhitelist(snap, time.Now())
	assert.Contains(t, w.Files.Allow, "/root")
}
