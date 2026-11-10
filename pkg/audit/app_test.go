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
