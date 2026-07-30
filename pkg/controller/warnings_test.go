package controller

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceGenerate_SnapshotWarningsPropagateToReport(t *testing.T) {
	dir := t.TempDir()
	service := Service{
		Collector: fakeCollector{
			snapshot: model.HostSnapshot{
				Hostname: "demo-host",
				CIDRs:    []string{"127.0.0.1/32"},
				RunningProcesses: []model.RunningProcess{
					{Command: "bash", Executable: "/usr/bin/bash"},
				},
				Warnings: []string{"proc/net/tcp unreadable"},
			},
		},
		Now: func() time.Time { return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC) },
	}

	outputPath := filepath.Join(dir, "whitelist.yaml")
	reportPath := filepath.Join(dir, "report.json")
	err := service.Generate(GenerateOptions{Mode: "monitor", OutputPath: outputPath, ReportPath: reportPath})
	require.NoError(t, err)

	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	assert.Contains(t, string(reportBytes), "proc/net/tcp unreadable")
}
