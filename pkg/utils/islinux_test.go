package utils

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLinux_ReturnsTrueOnLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		assert.True(t, isLinux())
	}
}
