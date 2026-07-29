package model
import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
)
func TestBuildWhitelist_WithCIDRs(t *testing.T) {
	snap := HostSnapshot{CIDRs: []string{"10.0.0.0/8", "::1/128"}, Hostname: "test"}
	wl := BuildWhitelist(snap, time.Now())
	assert.Contains(t, wl.Network.CIDRAllow, "10.0.0.0/8")
}
