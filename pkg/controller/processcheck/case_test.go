package processcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatcher_CaseSensitiveMatching(t *testing.T) {
	matcher := NewMatcher([]string{"Bash", "SSHD"})
	assert.True(t, matcher.Allowed("Bash", "systemd"))
	assert.False(t, matcher.Allowed("bash", "systemd"))
	assert.True(t, matcher.Allowed("curl", "SSHD"))
	assert.False(t, matcher.Allowed("curl", "sshd"))
}
