package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewApp_RegistersControllerCommand(t *testing.T) {
	app := NewApp("dev")
	commandNames := []string{}
	for _, command := range app.Commands {
		commandNames = append(commandNames, command.Name)
	}
	assert.Contains(t, commandNames, "controller")
}

func TestApp_ConfigFailureReturnsErrorBeforeStartingModules(t *testing.T) {
	for _, content := range []string{"", "policy: typo\n", "network: {enbale: true}\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if content != "" {
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		}
		err := NewApp("test").Run([]string{"safeguard", "--config", path})
		require.Error(t, err)
		assert.Contains(t, err.Error(), path)
		if content == "" {
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
	}
}
