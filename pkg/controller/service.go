package controller

import (
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
