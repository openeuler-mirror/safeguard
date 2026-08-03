package config
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestDefaultConfig_FileAccessAllowIncludesRoot(t *testing.T) {
	cfg := DefaultConfig()
	assert.Contains(t, cfg.RestrictedFileAccessConfig.Allow, "/")
}
func TestDefaultConfig_FileAccessDenyEmpty(t *testing.T) {
	cfg := DefaultConfig()
	assert.Empty(t, cfg.RestrictedFileAccessConfig.Deny)
}
