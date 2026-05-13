package model

import "time"

type Account struct {
	Username string `json:"username"`
	UID      uint   `json:"uid"`
	GID      uint   `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

type RunningProcess struct {
	PID        int    `json:"pid"`
	Command    string `json:"command"`
	Executable string `json:"executable"`
	UID        uint   `json:"uid"`
	GID        uint   `json:"gid"`
}

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

type Metadata struct {
	Hostname    string    `json:"hostname"`
	GeneratedAt time.Time `json:"generated_at"`
}

type NetworkWhitelist struct {
	CIDRAllow []string `json:"cidr_allow"`
	UIDAllow  []uint   `json:"uid_allow"`
	GIDAllow  []uint   `json:"gid_allow"`
}

type FileWhitelist struct {
	Allow []string `json:"allow"`
}

type ProcessWhitelist struct {
	Allow []string `json:"allow"`
}

type WhitelistModel struct {
	Metadata Metadata         `json:"metadata"`
	Network  NetworkWhitelist `json:"network"`
	Accounts []Account        `json:"accounts"`
	Files    FileWhitelist    `json:"files"`
	Process  ProcessWhitelist `json:"process"`
	Warnings []string         `json:"warnings"`
}
