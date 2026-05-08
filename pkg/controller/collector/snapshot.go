package collector

import (
	"os"

	"culinux/pkg/controller/model"
)

type SnapshotCollector struct {
	PasswdPath       string
	ProcRoot         string
	ProcNetPaths     []string
	HostnameFn       func() (string, error)
	InterfaceCIDRsFn func() ([]string, error)
}

func NewSnapshotCollector() SnapshotCollector {
	return SnapshotCollector{
		PasswdPath: "/etc/passwd",
		ProcRoot:   "/proc",
		ProcNetPaths: []string{
			"/proc/net/tcp",
			"/proc/net/tcp6",
			"/proc/net/udp",
			"/proc/net/udp6",
		},
		HostnameFn: os.Hostname,
		InterfaceCIDRsFn: func() ([]string, error) {
			return collectInterfaceCIDRs()
		},
	}
}

func (c SnapshotCollector) Collect() (model.HostSnapshot, error) {
	hostname, err := c.HostnameFn()
	if err != nil {
		return model.HostSnapshot{}, err
	}

	accounts, accountUIDs, accountGIDs, err := readPasswdAccounts(c.PasswdPath)
	if err != nil {
		return model.HostSnapshot{}, err
	}

	processes, processUIDs, processGIDs, executablePaths, err := readProcProcesses(c.ProcRoot)
	if err != nil {
		return model.HostSnapshot{}, err
	}

	interfaceCIDRs, err := c.InterfaceCIDRsFn()
	if err != nil {
		return model.HostSnapshot{}, err
	}

	procNetCIDRs, warnings := readProcNetCIDRs(c.ProcNetPaths)

	return model.HostSnapshot{
		Hostname:         hostname,
		CIDRs:            append(interfaceCIDRs, procNetCIDRs...),
		Accounts:         accounts,
		UIDs:             append(accountUIDs, processUIDs...),
		GIDs:             append(accountGIDs, processGIDs...),
		RunningProcesses: processes,
		ExecutablePaths:  executablePaths,
		Warnings:         warnings,
	}, nil
}
