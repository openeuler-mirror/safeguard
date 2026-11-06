package controller

import (
	"errors"
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

func TestServiceGenerate_ReturnsCollectorError(t *testing.T) {
	dir := t.TempDir()
	collectErr := errors.New("collect failed")
	service := Service{
		Collector: fakeCollector{err: collectErr},
		Now: func() time.Time {
			return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
		},
	}

	outputPath := filepath.Join(dir, "demo-whitelist.yaml")
	err := service.Generate(GenerateOptions{
		Mode:       "monitor",
		OutputPath: outputPath,
	})

	require.ErrorIs(t, err, collectErr)
	assert.ErrorContains(t, err, "collect host snapshot")
	assert.NoFileExists(t, outputPath)
}

func TestServiceGenerate_SkipsReportWhenReportPathIsEmpty(t *testing.T) {
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
		Now: func() time.Time {
			return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
		},
	}

	outputPath := filepath.Join(dir, "demo-whitelist.yaml")
	err := service.Generate(GenerateOptions{
		Mode:       "monitor",
		OutputPath: outputPath,
		ReportPath: "",
	})
	require.NoError(t, err)

	_, err = config.NewConfig(outputPath)
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "demo-whitelist.yaml", entries[0].Name())
}

func TestServiceGenerate_RejectsInvalidOptionsBeforeCollection(t *testing.T) {
	for _, tc := range []struct {
		mode, output, field string
	}{
		{"blok", "config.yaml", "mode"},
		{"", "config.yaml", "mode"},
		{"monitor", "", "output"},
	} {
		t.Run(tc.field+"/"+tc.mode, func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "report.json")
			// Nil dependencies ensure validation runs before collection.
			err := (Service{}).Generate(GenerateOptions{
				Mode: tc.mode, OutputPath: tc.output, ReportPath: report,
			})
			require.ErrorContains(t, err, tc.field)
			assert.NoFileExists(t, report)
		})
	}
}

func TestServiceGenerate_RejectsOutputReportAliases(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "config.yaml")
	hardlink, symlink := filepath.Join(root, "hardlink"), filepath.Join(root, "symlink")
	require.NoError(t, os.WriteFile(output, []byte("original"), 0o600))
	require.NoError(t, os.Link(output, hardlink))
	require.NoError(t, os.Symlink(output, symlink))
	cwd, err := os.Getwd()
	require.NoError(t, err)
	relative, err := filepath.Rel(cwd, output)
	require.NoError(t, err)
	for name, report := range map[string]string{
		"identical":  output,
		"normalized": root + "/unused/../config.yaml",
		"relative":   relative,
		"hardlink":   hardlink,
		"symlink":    symlink,
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(output, []byte("original"), 0o600))
			service := Service{Collector: fakeCollector{}, Now: time.Now}
			err := service.Generate(GenerateOptions{
				Mode: "monitor", OutputPath: output, ReportPath: report,
			})
			assert.ErrorContains(t, err, "different files")
			content, err := os.ReadFile(output)
			require.NoError(t, err)
			assert.Equal(t, "original", string(content))
		})
	}
}

func TestServiceGenerate_RejectsIdenticalMissingPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	err := (Service{}).Generate(GenerateOptions{
		Mode: "monitor", OutputPath: path, ReportPath: path,
	})
	require.ErrorContains(t, err, "different files")
	assert.NoFileExists(t, path)
}

func TestServiceGenerate_IdentifiesFailedOutput(t *testing.T) {
	for _, reportFailure := range []bool{false, true} {
		root := t.TempDir()
		output, report := root, ""
		stage, path := "write configuration", root
		if reportFailure {
			output, report = filepath.Join(root, "config.yaml"), root
			stage = "write report"
		}
		service := Service{Collector: fakeCollector{}, Now: time.Now}
		err := service.Generate(GenerateOptions{Mode: "monitor", OutputPath: output, ReportPath: report})
		require.ErrorContains(t, err, stage)
		assert.ErrorContains(t, err, path)
		var pathErr *os.PathError
		require.ErrorAs(t, err, &pathErr)
		assert.Equal(t, path, pathErr.Path)
	}
}

func TestServiceGenerate_ReportEncodingFailureDoesNotWriteFiles(t *testing.T) {
	for _, existing := range []bool{false, true} {
		root := t.TempDir()
		output, report := filepath.Join(root, "nested", "config.yaml"), filepath.Join(root, "report.json")
		if existing {
			require.NoError(t, os.MkdirAll(filepath.Dir(output), 0o700))
			require.NoError(t, os.WriteFile(output, []byte("original config"), 0o600))
			require.NoError(t, os.WriteFile(report, []byte("original report"), 0o600))
		}
		service := Service{
			Collector: fakeCollector{},
			Now:       func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		}
		err := service.Generate(GenerateOptions{Mode: "monitor", OutputPath: output, ReportPath: report})
		require.ErrorContains(t, err, "encode report")
		if existing {
			for path, original := range map[string]string{output: "original config", report: "original report"} {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, original, string(data))
			}
		} else {
			assert.NoFileExists(t, output)
			assert.NoFileExists(t, report)
			assert.NoDirExists(t, filepath.Dir(output))
		}
	}
}

func TestServiceGenerateMissingParentAliases(t *testing.T) {
	for _, nested := range []string{"", "not-yet/child"} {
		root := t.TempDir()
		real := filepath.Join(root, "real")
		alias := filepath.Join(root, "alias")
		require.NoError(t, os.Mkdir(real, 0755))
		require.NoError(t, os.Symlink(real, alias))
		output := filepath.Join(real, nested, "config.yaml")
		report := filepath.Join(alias, nested, "config.yaml")
		service := Service{Collector: fakeCollector{}, Now: time.Now}
		err := service.Generate(GenerateOptions{Mode: "monitor", OutputPath: output, ReportPath: report})
		require.ErrorContains(t, err, "different files")
		require.NoFileExists(t, output)
	}
}

func TestServiceGenerateMissingDependencies(t *testing.T) {
	for _, tc := range []struct {
		service Service
		missing string
	}{
		{Service{Now: time.Now}, "collector"},
		{Service{Collector: fakeCollector{}}, "clock"},
	} {
		output := filepath.Join(t.TempDir(), "config.yaml")
		require.NotPanics(t, func() {
			err := tc.service.Generate(GenerateOptions{Mode: "monitor", OutputPath: output})
			require.ErrorContains(t, err, tc.missing)
		})
		require.NoFileExists(t, output)
	}
}
