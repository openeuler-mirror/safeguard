package collector
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestParseStatusIDs_ValidUIDGID(t *testing.T) {
	uid, gid := parseStatusIDs("Uid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\n")
	assert.Equal(t, uint(1000), uid)
	assert.Equal(t, uint(100), gid)
}
func TestParseStatusIDs_EmptyContent(t *testing.T) {
	uid, gid := parseStatusIDs("")
	assert.Equal(t, uint(0), uid)
	assert.Equal(t, uint(0), gid)
}
