package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLinux_CurrentSystem(t *testing.T) {
	result := isLinux()
	assert.True(t, result)
}

