package audit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	log "culinux/pkg/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditSignalContextSIGTERM(t *testing.T) {
	if os.Getenv("SAFEGUARD_TEST_SIGNAL_CHILD") == "1" {
		ctx, cancel := auditSignalContext(context.Background())
		defer cancel()
		fmt.Println("ready")
		<-ctx.Done()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditSignalContextSIGTERM$")
	cmd.Env = append(os.Environ(), "SAFEGUARD_TEST_SIGNAL_CHILD=1")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer cmd.Process.Kill()
	scanner := bufio.NewScanner(stdout)
	ready := make(chan string, 1)
	go func() {
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	select {
	case line := <-ready:
		require.Equal(t, "ready", line)
	case <-time.After(5 * time.Second):
		t.Fatal("child did not become ready")
	}
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not cancel the child context")
	}
}

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

func TestAppClosesLogOnStartupError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("audit startup requires root")
	}
	previous := log.Logger.Logger.Out
	t.Cleanup(func() { log.Logger.Logger.SetOutput(previous) })
	t.Setenv("SKIP_COMPATIBLE_CHECK", "1")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf("process:\n  enable: true\nlog:\n  output: %s\n", filepath.Join(dir, "audit.log"))
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))
	err := NewApp("test").Run([]string{"safeguard", "--config", configPath, "--startup-timeout", "-1s"})
	require.ErrorContains(t, err, "startup timeout")
	assert.Same(t, os.Stdout, log.Logger.Logger.Out)
}

func TestAppRejectsInvalidLogEnvironment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("audit startup requires root")
	}
	previous := log.Logger.Logger.Out
	t.Cleanup(func() { log.Logger.Logger.SetOutput(previous) })
	t.Setenv("SKIP_COMPATIBLE_CHECK", "1")
	t.Setenv("SAFEGUARD_LOG", "bad-level")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("process:\n  enable: true\n"), 0600))
	err := NewApp("test").Run([]string{"safeguard", "--config", configPath, "--startup-timeout", "-1s"})
	require.ErrorContains(t, err, "BAD-LEVEL")
	assert.Same(t, os.Stdout, log.Logger.Logger.Out)
}
