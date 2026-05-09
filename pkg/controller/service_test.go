package controller

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"culinux/pkg/config"
	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCollector struct {
	snapshot model.HostSnapshot
	err      error
}

func (f fakeCollector) Collect() (model.HostSnapshot, error) {
	return f.snapshot, f.err
}

func TestServiceGenerate_WritesConfigAndReport(t *testing.T) {
	dir := t.TempDir()
	service := Service{
		Collector: fakeCollector{
			snapshot: model.HostSnapshot{
				Hostname: "demo-host",
				CIDRs:    []string{"127.0.0.1/32"},
				Accounts: []model.Account{
					{Username: "root", UID: 0, GID: 0, HomeDir: "/root", Shell: "/bin/bash"},
				},
				UIDs: []uint{0},
				GIDs: []uint{0},
				RunningProcesses: []model.RunningProcess{
					{PID: 1, Command: "bash", Executable: "/usr/bin/bash", UID: 0, GID: 0},
				},
				ExecutablePaths: []string{"/usr/bin/bash"},
			},
		},
		Now: func() time.Time {
			return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
		},
	}

	outputPath := filepath.Join(dir, "demo-whitelist.yaml")
	reportPath := filepath.Join(dir, "demo-whitelist-report.json")

	err := service.Generate(GenerateOptions{
		Mode:       "monitor",
		OutputPath: outputPath,
		ReportPath: reportPath,
	})
	require.NoError(t, err)

	cfg, err := config.NewConfig(outputPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"bash"}, cfg.RestrictedProcessConfig.Allow)

	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	assert.Contains(t, string(reportBytes), "\"hostname\": \"demo-host\"")
}
