package controller

import (
	"fmt"
	"os"
	"path/filepath"
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
		output, err := filepath.Abs(options.OutputPath)
		if err != nil {
			return fmt.Errorf("resolve output path: %w", err)
		}
		report, err := filepath.Abs(options.ReportPath)
		if err != nil {
			return fmt.Errorf("resolve report path: %w", err)
		}
		outputInfo, outputErr := os.Stat(output)
		reportInfo, reportErr := os.Stat(report)
		if output == report || (outputErr == nil && reportErr == nil && os.SameFile(outputInfo, reportInfo)) {
			return fmt.Errorf("output and report must refer to different files")
		}
	}

	snapshot, err := s.Collector.Collect()
	if err != nil {
		return fmt.Errorf("collect host snapshot: %w", err)
	}

	whitelist := model.BuildWhitelist(snapshot, s.Now())

	yamlBytes, err := render.MarshalConfigYAML(whitelist, options.Mode)
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := render.WriteFile(options.OutputPath, yamlBytes); err != nil {
		return fmt.Errorf("write configuration %q: %w", options.OutputPath, err)
	}

	if options.ReportPath != "" {
		reportBytes, err := render.MarshalReportJSON(whitelist)
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
		if err := render.WriteFile(options.ReportPath, reportBytes); err != nil {
			return fmt.Errorf("write report %q: %w", options.ReportPath, err)
		}
	}

	return nil
}
