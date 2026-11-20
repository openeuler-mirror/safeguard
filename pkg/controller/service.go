package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"culinux/pkg/controller/collector"
	"culinux/pkg/controller/model"
	"culinux/pkg/controller/render"
)

type SnapshotCollector interface {
	Collect() (model.HostSnapshot, error)
}

type GenerateOptions struct {
	Mode       string
	OutputPath string
	ReportPath string
}

type Service struct {
	Collector SnapshotCollector
	Now       func() time.Time
}

func NewService() Service {
	return Service{
		Collector: collector.NewSnapshotCollector(),
		Now:       time.Now,
	}
}

func (s Service) Generate(options GenerateOptions) error {
	if options.Mode != "monitor" && options.Mode != "block" {
		return fmt.Errorf("invalid mode %q: must be monitor or block", options.Mode)
	}
	if options.OutputPath == "" {
		return fmt.Errorf("output path must not be empty")
	}
	if options.ReportPath != "" {
		output, err := resolveOutputPath(options.OutputPath)
		if err != nil {
			return fmt.Errorf("resolve output path: %w", err)
		}
		report, err := resolveOutputPath(options.ReportPath)
		if err != nil {
			return fmt.Errorf("resolve report path: %w", err)
		}
		outputInfo, outputErr := os.Stat(options.OutputPath)
		reportInfo, reportErr := os.Stat(options.ReportPath)
		if output == report || (outputErr == nil && reportErr == nil && os.SameFile(outputInfo, reportInfo)) {
			return fmt.Errorf("output and report must refer to different files")
		}
	}

	if s.Collector == nil {
		return fmt.Errorf("collector is not initialized")
	}
	if s.Now == nil {
		return fmt.Errorf("clock is not initialized")
	}
	snapshot, err := s.Collector.Collect()
	if err != nil {
		return fmt.Errorf("collect host snapshot: %w", err)
	}

	whitelist := model.BuildWhitelist(snapshot, s.Now())
	if len(whitelist.Warnings) > 0 && options.ReportPath == "" {
		return fmt.Errorf("report path is required when generation produces warnings")
	}

	yamlBytes, err := render.MarshalConfigYAML(whitelist, options.Mode)
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	var reportBytes []byte
	if options.ReportPath != "" {
		reportBytes, err = render.MarshalReportJSON(whitelist)
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
	}
	if err := render.WriteFile(options.OutputPath, yamlBytes); err != nil {
		return fmt.Errorf("write configuration %q: %w", options.OutputPath, err)
	}
	if options.ReportPath != "" {
		if err := render.WriteFile(options.ReportPath, reportBytes); err != nil {
			return fmt.Errorf("write report %q: %w", options.ReportPath, err)
		}
	}

	return nil
}

func resolveOutputPath(path string) (string, error) {
	current := string(filepath.Separator)
	if !filepath.IsAbs(path) {
		var err error
		current, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	parts := strings.Split(path, string(filepath.Separator))
	hops := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if os.IsNotExist(err) || err == nil && info.Mode()&os.ModeSymlink == 0 {
			current = candidate
			continue
		}
		if err != nil {
			return "", err
		}
		hops++
		if hops > 40 {
			return "", fmt.Errorf("too many symbolic links resolving %q", path)
		}
		target, err := os.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			current = string(filepath.Separator)
		}
		parts = append(strings.Split(target, string(filepath.Separator)), parts...)
	}
	return current, nil
}
