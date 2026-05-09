package controller

import (
	"time"

	"culinux/pkg/controller/collector"
	"culinux/pkg/controller/model"
	"culinux/pkg/controller/render"
)

// SnapshotCollector defines interface for collecting host snapshot
type SnapshotCollector interface {
	Collect() (model.HostSnapshot, error)
}

// GenerateOptions holds options for whitelist generation
type GenerateOptions struct {
	Mode       string
	OutputPath string
	ReportPath string
}

// Service provides whitelist generation functionality
type Service struct {
	Collector SnapshotCollector
	Now       func() time.Time
}

// NewService creates a new Service instance
func NewService() Service {
	return Service{
		Collector: collector.NewSnapshotCollector(),
		Now:       time.Now,
	}
}

// Generate collects host data and generates whitelist configuration
func (s Service) Generate(options GenerateOptions) error {
	snapshot, err := s.Collector.Collect()
	if err != nil {
		return err
	}

	whitelist := model.BuildWhitelist(snapshot, s.Now())

	yamlBytes, err := render.MarshalConfigYAML(whitelist, options.Mode)
	if err != nil {
		return err
	}
	if err := render.WriteFile(options.OutputPath, yamlBytes); err != nil {
		return err
	}

	if options.ReportPath != "" {
		reportBytes, err := render.MarshalReportJSON(whitelist)
		if err != nil {
			return err
		}
		if err := render.WriteFile(options.ReportPath, reportBytes); err != nil {
			return err
		}
	}

	return nil
}
