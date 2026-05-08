package model

import "time"

// DefaultFileAllow contains default allowed file paths
var defaultFileAllow = []string{
	"/", "/bin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/etc",
	"/tmp", "/var", "/run", "/usr/lib", "/home", "/root",
}

// BuildWhitelist creates a WhitelistModel from HostSnapshot
func BuildWhitelist(snapshot HostSnapshot, generatedAt time.Time) WhitelistModel {
	// TODO: implement
	return WhitelistModel{}
}
