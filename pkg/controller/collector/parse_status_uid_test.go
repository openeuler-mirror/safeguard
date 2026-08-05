package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStatusIDs_LargeUID(t *testing.T) {
	content := "Name:\ttest\nUid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n"
	uid, gid := parseStatusIDs(content)
	assert.Equal(t, uint(65534), uid)
	assert.Equal(t, uint(65534), gid)
}
