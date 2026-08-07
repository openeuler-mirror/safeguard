package processcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMatcher_SingleEntry(t *testing.T) {
	m := NewMatcher([]string{"bash"})
	assert.True(t, m.Allowed("bash", "sh"))
}

func TestMatcher_DifferentCommand(t *testing.T) {
	m := NewMatcher([]string{"bash"})
	assert.False(t, m.Allowed("python", "sh"))
}
