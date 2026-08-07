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

	// A single point-in-time snapshot does not see: cron jobs, failover
	// paths, lazily-loaded dependencies, services that restart later, or
	// future remote endpoints. Generating a block-mode config from one
	// snapshot can therefore lock the operator out of the host. Surface
	// this in the report so the operator follows the recommended flow:
	// continuous learning -> aggregate/manual review -> monitor verify
	// -> block. See audit #31.
	if options.Mode == "block" {
		blockWarning := "block mode generated from a single snapshot; " +
			"recommended flow is learn -> review -> monitor -> block. " +
			"This whitelist only reflects processes and connections " +
			"observed at generation time and may block future legit " +
			"traffic (cron, failover, restarts, new peers)."
		whitelist.Warnings = append(whitelist.Warnings, blockWarning)
	}

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
