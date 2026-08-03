package model
import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
)
func TestBuildWhitelist_MetadataHostname(t *testing.T) {
	snap := HostSnapshot{Hostname: "myhost"}
	wl := BuildWhitelist(snap, time.Now())
	assert.Equal(t, "myhost", wl.Metadata.Hostname)
}
func TestBuildWhitelist_MetadataGeneratedAt(t *testing.T) {
	now := time.Now()
	snap := HostSnapshot{Hostname: "test"}
	wl := BuildWhitelist(snap, now)
	assert.Equal(t, now, wl.Metadata.GeneratedAt)
}
