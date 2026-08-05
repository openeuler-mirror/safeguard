package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStatusIDs_MissingFields(t *testing.T) {
	content := "Name:\ttest\nState:\tS\n"
	uid, gid := parseStatusIDs(content)
	assert.Equal(t, uint(0), uid)
	assert.Equal(t, uint(0), gid)
}

