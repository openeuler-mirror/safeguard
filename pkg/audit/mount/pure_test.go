package mount

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRetToaction_Allowed(t *testing.T) {
	assert.Equal(t, "ALLOWED", retToaction(0))
}

func TestRetToaction_Monitor(t *testing.T) {
	assert.Equal(t, "MONITOR", retToaction(1))
}

func TestRetToaction_Blocked(t *testing.T) {
	assert.Equal(t, "BLOCKED", retToaction(-1))
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

func TestAuditPathBytes(t *testing.T) {
	var path [PATH_MAX]byte
	copy(path[:], []byte("/数据/文件"))
	copy(path[32:], []byte("ignored"))
	assert.Equal(t, "/数据/文件", pathToString(path))
	path = [PATH_MAX]byte{0xff, 0, 0xaa}
	assert.Equal(t, string([]byte{0xff}), pathToString(path))
	for i := range path {
		path[i] = 'a'
	}
	assert.Len(t, pathToString(path), PATH_MAX)
}
