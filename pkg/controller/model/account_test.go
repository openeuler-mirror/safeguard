package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildWhitelist_AccountsHomeDirsAddedToFileAllow(t *testing.T) {
	whitelist := BuildWhitelist(HostSnapshot{
		Accounts: []Account{
			{Username: "root", UID: 0, GID: 0, HomeDir: "/root", Shell: "/bin/bash"},
			{Username: "app", UID: 1000, GID: 1000, HomeDir: "/home/app", Shell: "/bin/bash"},
			{Username: "empty", UID: 1001, GID: 1001, HomeDir: "", Shell: "/sbin/nologin"},
		},
	}, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))

	assert.Contains(t, whitelist.Files.Allow, "/root")
	assert.Contains(t, whitelist.Files.Allow, "/home/app")
}
