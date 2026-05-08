package model

import "time"

// Metadata holds whitelist generation metadata
type Metadata struct {
	Hostname    string    `json:"hostname"`
	GeneratedAt time.Time `json:"generated_at"`
}

// HostSnapshot represents collected host data
type HostSnapshot struct {
	Hostname         string           `json:"hostname"`
	CIDRs            []string         `json:"cidrs"`
	Accounts         []Account        `json:"accounts"`
	UIDs             []uint           `json:"uids"`
	GIDs             []uint           `json:"gids"`
	RunningProcesses []RunningProcess `json:"running_processes"`
	ExecutablePaths  []string         `json:"executable_paths"`
	Warnings         []string         `json:"warnings"`
}

// Account represents a user account from /etc/passwd
type Account struct {
	Username string `json:"username"`
	UID      uint   `json:"uid"`
	GID      uint   `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

// RunningProcess represents a running process from /proc
type RunningProcess struct {
	PID        int    `json:"pid"`
	Command    string `json:"command"`
	Executable string `json:"executable"`
	UID        uint   `json:"uid"`
	GID        uint   `json:"gid"`
}
