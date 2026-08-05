package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSnapshotCollector_ReturnsCollector(t *testing.T) {
	c := NewSnapshotCollector()
	assert.NotNil(t, c)
}
