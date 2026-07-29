package controller
import (
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestNewCommand_HasControllerName(t *testing.T) {
	cmd := NewCommand()
	assert.Equal(t, "controller", cmd.Name)
}
func TestNewCommand_HasGenerateSubcommand(t *testing.T) {
	cmd := NewCommand()
	assert.Len(t, cmd.Subcommands, 1)
	assert.Equal(t, "generate", cmd.Subcommands[0].Name)
}
