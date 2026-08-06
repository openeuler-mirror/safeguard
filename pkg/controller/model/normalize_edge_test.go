package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeProcessAllowEntry_EmptyCommand(t *testing.T) {
	result := normalizeProcessAllowEntry(RunningProcess{Command: ""})
	assert.Equal(t, "", result)
}

func TestNormalizeProcessAllowEntry_WhitespaceCommand(t *testing.T) {
	result := normalizeProcessAllowEntry(RunningProcess{Command: "  "})
	assert.Equal(t, "", result)
}

