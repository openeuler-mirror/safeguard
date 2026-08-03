package model
import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
)
func TestBuildWhitelist_ExecutablePathsAddedToFileAllow(t *testing.T) {
	snap := HostSnapshot{ExecutablePaths: []string{"/usr/bin/custom"}, Hostname: "test"}
	wl := BuildWhitelist(snap, time.Now())
	assert.Contains(t, wl.Files.Allow, "/usr/bin/custom")
}
