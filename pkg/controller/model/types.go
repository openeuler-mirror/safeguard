package model

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
