package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewApp_RegistersControllerCommand(t *testing.T) {
	app := NewApp("dev")
	commandNames := []string{}
	for _, command := range app.Commands {
		commandNames = append(commandNames, command.Name)
	}
	assert.Contains(t, commandNames, "controller")
}
