package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKernelVersion_ReturnsNonEmpty(t *testing.T) {
	ver, err := getKernelVersion()
	assert.NoError(t, err)
	assert.NotEmpty(t, ver)
}

