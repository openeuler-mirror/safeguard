package controller

import (
	"path/filepath"
	"testing"
	"time"

	"culinux/pkg/config"
	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceGenerate_BlockModeProducesBlockConfig(t *testing.T) {
	dir := t.TempDir()
	service := Service{
		Collector: fakeCollector{
			snapshot: model.HostSnapshot{
				Hostname: "demo-host",
				CIDRs:    []string{"127.0.0.1/32"},
				RunningProcesses: []model.RunningProcess{
					{Command: "bash", Executable: "/usr/bin/bash"},
				},
			},
		},
		Now: func() time.Time { return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC) },
	}

	outputPath := filepath.Join(dir, "block-whitelist.yaml")
	err := service.Generate(GenerateOptions{Mode: "block", OutputPath: outputPath})
	require.NoError(t, err)

	cfg, err := config.NewConfig(outputPath)
	require.NoError(t, err)
	assert.Equal(t, "block", cfg.RestrictedNetworkConfig.Mode)
	assert.Equal(t, "block", cfg.RestrictedFileAccessConfig.Mode)
}
