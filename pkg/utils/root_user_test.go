package utils
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestAmIRootUser_CurrentProcess(t *testing.T) {
	result := AmIRootUser()
	assert.IsType(t, true, result)
	_ = result
}
