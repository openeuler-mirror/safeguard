package model

// Account represents a user account from /etc/passwd
type Account struct {
	Username string `json:"username"`
	UID      uint   `json:"uid"`
	GID      uint   `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}
