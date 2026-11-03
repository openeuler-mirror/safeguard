package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledModulesExitBeforeRuntimeSideEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disabled.yaml")
	// Defaults disable every module; this log path must never be opened.
	if err := os.WriteFile(path, []byte("log:\n  output: /missing-safeguard-parent/audit.log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	notified := false
	app := NewApp("test", WithReadyNotification(func(context.Context) error { notified = true; return nil }))
	if err := app.Run([]string{"safeguard", "--config", path}); err != nil {
		t.Fatal(err)
	}
	if notified {
		t.Fatal("reported running modules for an empty task set")
	}
	for _, flag := range []string{"--startup-timeout", "--shutdown-timeout"} {
		if err := NewApp("test").Run([]string{"safeguard", "--config", path, flag, "-1s"}); err == nil {
			t.Fatalf("accepted negative %s", flag)
		}
	}
}
