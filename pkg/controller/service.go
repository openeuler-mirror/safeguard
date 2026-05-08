package controller

import "time"

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
		Now: time.Now,
	}
}

// SnapshotCollector defines interface for collecting host snapshot
type SnapshotCollector interface {
	Collect() (HostSnapshot, error)
}

// HostSnapshot represents collected host data
type HostSnapshot struct {
	Hostname string
}
