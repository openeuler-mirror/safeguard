package model

import "time"

// Account represents a user account from /etc/passwd.
type Account struct {
	Username string `json:"username"`
	UID      uint   `json:"uid"`
	GID      uint   `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

// RunningProcess represents a currently running process.
type RunningProcess struct {
	PID        int    `json:"pid"`
	Command    string `json:"command"`
	Executable string `json:"executable"`
	UID        uint   `json:"uid"`
	GID        uint   `json:"gid"`
}

// HostSnapshot contains all collected data about the host.
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

// Metadata contains generation metadata for the whitelist.
type Metadata struct {
	Hostname    string    `json:"hostname"`
	GeneratedAt time.Time `json:"generated_at"`
}

// NetworkWhitelist contains network-related whitelist entries.
type NetworkWhitelist struct {
	CIDRAllow []string `json:"cidr_allow"`
	UIDAllow  []uint   `json:"uid_allow"`
	GIDAllow  []uint   `json:"gid_allow"`
}

// FileWhitelist contains file access whitelist entries.
type FileWhitelist struct {
	Allow []string `json:"allow"`
}

// ProcessWhitelist contains process execution whitelist entries.
type ProcessWhitelist struct {
	Allow []string `json:"allow"`
}

// WhitelistModel is the complete whitelist model generated from host data.
type WhitelistModel struct {
	Metadata Metadata         `json:"metadata"`
	Network  NetworkWhitelist `json:"network"`
	Accounts []Account        `json:"accounts"`
	Files    FileWhitelist    `json:"files"`
	Process  ProcessWhitelist `json:"process"`
	Warnings []string         `json:"warnings"`
}
