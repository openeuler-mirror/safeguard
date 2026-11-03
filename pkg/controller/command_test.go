package controller

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"culinux/pkg/config"

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

func TestValidatePrintsNormalizedConfigWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.yaml")
	source := []byte("network:\n  enable: true\n  uid: {allow: [9, 1, 9]}\n  cidr: {allow: [192.0.2.129/24]}\n")
	require.NoError(t, os.WriteFile(path, source, 0600))
	var output bytes.Buffer
	app := &cli.App{Commands: []*cli.Command{NewCommand()}, Writer: &output}
	require.NoError(t, app.Run([]string{"safeguard", "controller", "validate", "--normalized", "--config", path}))
	normalized := filepath.Join(t.TempDir(), "normalized.yaml")
	require.NoError(t, os.WriteFile(normalized, output.Bytes(), 0600))
	cfg, err := config.NewConfig(normalized)
	require.NoError(t, err)
	require.Equal(t, []uint{1, 9}, cfg.UID.Allow)
	require.Equal(t, []string{"192.0.2.0/24"}, cfg.CIDR.Allow)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, source, after)
	app.Writer = closedConfigWriter{}
	require.ErrorIs(t, app.Run([]string{"safeguard", "controller", "validate", "--normalized", "--config", path}), io.ErrClosedPipe)
}

type closedConfigWriter struct{}

func (closedConfigWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
