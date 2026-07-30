package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_DeletedProcessExeStripped(t *testing.T) {
	whitelist := BuildWhitelist(HostSnapshot{
		RunningProcesses: []RunningProcess{
			{Command: "nginx (deleted)", Executable: "/usr/sbin/nginx (deleted)"},
			{Command: "bash"},
		},
	}, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))

	assert.Contains(t, whitelist.Process.Allow, "nginx")
	assert.Contains(t, whitelist.Process.Allow, "bash")
}
