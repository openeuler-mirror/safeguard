package processcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatcher_AllowsWhenCommandOrParentMatches(t *testing.T) {
	matcher := NewMatcher([]string{"bash", "sshd"})
	assert.True(t, matcher.Allowed("bash", "systemd"))
	assert.True(t, matcher.Allowed("curl", "sshd"))
	assert.False(t, matcher.Allowed("curl", "python"))
}

func TestMatcher_EmptyAllowListAllowsEverything(t *testing.T) {
	matcher := NewMatcher(nil)
	assert.True(t, matcher.Allowed("curl", "python"))
}
