package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_ProcessAllowFromRunning(t *testing.T) {
	snap := HostSnapshot{
		RunningProcesses: []RunningProcess{{Command: "bash", Executable: "/usr/bin/bash"}},
	}
	w := BuildWhitelist(snap, time.Now())
	assert.Contains(t, w.Process.Allow, "bash")
}
