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

// TestIntegration_GenerateToConfig tests full flow from generate to config load
func TestIntegration_GenerateToConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "whitelist.yaml")
	reportPath := filepath.Join(dir, "report.json")

	// Use real service
	service := NewService()
	err := service.Generate(GenerateOptions{
		Mode:       "monitor",
		OutputPath: outputPath,
		ReportPath: reportPath,
	})
	require.NoError(t, err)

	// Verify output files exist
	_, err = os.Stat(outputPath)
	require.NoError(t, err)
	_, err = os.Stat(reportPath)
	require.NoError(t, err)

	// Verify config can be loaded
	cfg, err := config.NewConfig(outputPath)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

// TestIntegration_BuildWhitelistFromRealHost tests with real host data
func TestIntegration_BuildWhitelistFromRealHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	collector := NewService().Collector
	snapshot, err := collector.Collect()
	require.NoError(t, err)

	// Verify snapshot has expected data
	assert.NotEmpty(t, snapshot.Hostname)
	assert.NotEmpty(t, snapshot.Accounts)
	assert.NotEmpty(t, snapshot.RunningProcesses)

	// Build whitelist
	whitelist := model.BuildWhitelist(snapshot, time.Now())
	assert.NotEmpty(t, whitelist.Process.Allow)
}
