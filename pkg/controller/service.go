package controller

// SnapshotCollector defines interface for collecting host snapshot
type SnapshotCollector interface {
	Collect() (HostSnapshot, error)
}

// HostSnapshot represents collected host data
type HostSnapshot struct {
	Hostname string
}
