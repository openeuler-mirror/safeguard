package render

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteFile_InvalidPath(t *testing.T) {
	err := WriteFile("/proc/nonexistent/path/file.txt", []byte("test"))
	assert.Error(t, err)
}

func TestWriteFile_ValidPath(t *testing.T) {
	dir := os.TempDir()
	path := filepath.Join(dir, "safeguard_test_write")
	defer os.Remove(path)
	err := WriteFile(path, []byte("hello"))
	assert.NoError(t, err)
	data, _ := os.ReadFile(path)
	assert.Equal(t, "hello", string(data))
}
