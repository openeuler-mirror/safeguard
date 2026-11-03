package controller

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestNewCommand_HasControllerName(t *testing.T) {
	cmd := NewCommand()
	assert.Equal(t, "controller", cmd.Name)
}
func TestNewCommand_HasGenerateSubcommand(t *testing.T) {
	cmd := NewCommand()
	assert.NotEmpty(t, cmd.Subcommands)
	assert.Equal(t, "generate", cmd.Subcommands[0].Name)
}

func TestControllerValidateCommand(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		valid         bool
	}{
		{"valid", "policy: whitelist\n", true},
		{"invalid policy", "policy: typo\n", false},
		{"unknown field", "network: {enbale: true}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))
			var output bytes.Buffer
			app := &cli.App{Commands: []*cli.Command{NewCommand()}, Writer: &output}
			err := app.Run([]string{"safeguard", "controller", "validate", "--config", path})
			if tc.valid {
				require.NoError(t, err)
				assert.Contains(t, output.String(), "Configuration is valid: "+path)
			} else {
				require.Error(t, err)
				assert.Empty(t, output.String())
			}
		})
	}
}

func TestControllerValidateRequiresConfigPath(t *testing.T) {
	app := &cli.App{Commands: []*cli.Command{NewCommand()}, Writer: &bytes.Buffer{}}
	err := app.Run([]string{"safeguard", "controller", "validate"})
	require.ErrorContains(t, err, "config")
}
