package model
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestUniqueStrings_SortedOutput(t *testing.T) {
	result := uniqueStrings([]string{"z", "a", "m"})
	assert.Equal(t, []string{"a", "m", "z"}, result)
}
func TestUniqueUints_SortedOutput(t *testing.T) {
	result := uniqueUints([]uint{300, 100, 200})
	assert.Equal(t, []uint{100, 200, 300}, result)
}
