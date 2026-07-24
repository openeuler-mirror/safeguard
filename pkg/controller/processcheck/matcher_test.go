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

func TestMatcher_TrimsAndIgnoresBlankAllowEntries(t *testing.T) {
	matcher := NewMatcher([]string{" bash ", "", " \t ", "sshd"})

	assert.True(t, matcher.Allowed("bash", "systemd"))
	assert.True(t, matcher.Allowed("curl", "sshd"))
	assert.False(t, matcher.Allowed("", ""))
}

func TestMatcher_UsesExactCommandAndParentMatches(t *testing.T) {
	matcher := NewMatcher([]string{"sh"})

	tests := []struct {
		name    string
		command string
		parent  string
		allowed bool
	}{
		{name: "command exact match", command: "sh", parent: "systemd", allowed: true},
		{name: "parent exact match", command: "curl", parent: "sh", allowed: true},
		{name: "command substring does not match", command: "bash", parent: "systemd", allowed: false},
		{name: "parent substring does not match", command: "curl", parent: "sshd", allowed: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.allowed, matcher.Allowed(test.command, test.parent))
		})
	}
}
