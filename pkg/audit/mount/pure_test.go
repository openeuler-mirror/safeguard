package mount

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRetToAction_Allowed(t *testing.T) {
	assert.Equal(t, "ALLOWED", retToAction(0))
}

func TestRetToAction_Monitor(t *testing.T) {
	assert.Equal(t, "MONITOR", retToAction(1))
}

func TestRetToAction_Blocked(t *testing.T) {
	assert.Equal(t, "BLOCKED", retToAction(-1))
}

func TestPathToString_StopsAtNull(t *testing.T) {
	var path [PATH_MAX]byte
	copy(path[:], "/mnt/data")
	result := pathToString(path)
	assert.Equal(t, "/mnt/data", result)
}

func TestPathToString_EmptyPath(t *testing.T) {
	var path [PATH_MAX]byte
	result := pathToString(path)
	assert.Equal(t, "", result)
}
