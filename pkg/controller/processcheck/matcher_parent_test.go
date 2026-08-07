package processcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatcher_AllowedByParent(t *testing.T) {
	m := NewMatcher([]string{"sh"})
	assert.True(t, m.Allowed("bash", "sh"))
}

func TestMatcher_NeitherMatches(t *testing.T) {
	m := NewMatcher([]string{"bash"})
	assert.False(t, m.Allowed("python", "sh"))
}
