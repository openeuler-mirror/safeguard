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

// NetworkWhitelist holds network whitelist configuration
type NetworkWhitelist struct {
	CIDRAllow []string `json:"cidr_allow"`
	UIDAllow  []uint   `json:"uid_allow"`
	GIDAllow  []uint   `json:"gid_allow"`
}

// FileWhitelist holds file access whitelist configuration
type FileWhitelist struct {
	Allow []string `json:"allow"`
}

// ProcessWhitelist holds process whitelist configuration
type ProcessWhitelist struct {
	Allow []string `json:"allow"`
}

// WhitelistModel is the complete whitelist configuration model
type WhitelistModel struct {
	Metadata Metadata         `json:"metadata"`
	Network  NetworkWhitelist `json:"network"`
	Accounts []Account        `json:"accounts"`
	Files    FileWhitelist    `json:"files"`
	Process  ProcessWhitelist `json:"process"`
	Warnings []string         `json:"warnings"`
}
