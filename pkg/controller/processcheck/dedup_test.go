package processcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMatcher_DeduplicatesEntries(t *testing.T) {
	matcher := NewMatcher([]string{"bash", "bash", "sshd", "sshd"})
	assert.True(t, matcher.Allowed("bash", "systemd"))
	assert.True(t, matcher.Allowed("curl", "sshd"))
	assert.False(t, matcher.Allowed("curl", "python"))
}

func TestNewMatcher_AllWhitespaceProducesEmptyAllowList(t *testing.T) {
	matcher := NewMatcher([]string{"  ", "\t", ""})
	assert.True(t, matcher.Allowed("anything", "anything"))
}
