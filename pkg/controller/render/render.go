package render

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"culinux/pkg/config"
	"culinux/pkg/controller/model"

	"gopkg.in/yaml.v2"
)

// BuildConfig maps a WhitelistModel into a safeguard Config.
func BuildConfig(whitelist model.WhitelistModel, mode string) config.Config {
	cfg := config.DefaultConfig()
	cfg.Policy = "whitelist" // controller 生成为白名单模式
	// 启用所有模块
	cfg.RestrictedNetworkConfig.Enable = true
	cfg.RestrictedNetworkConfig.Mode = mode
	cfg.RestrictedNetworkConfig.Target = "host"
	cfg.RestrictedNetworkConfig.CIDR.Allow = whitelist.Network.CIDRAllow
	cfg.RestrictedNetworkConfig.UID.Allow = whitelist.Network.UIDAllow
	cfg.RestrictedNetworkConfig.GID.Allow = whitelist.Network.GIDAllow
	cfg.RestrictedNetworkConfig.Command.Allow = []string{}
	cfg.RestrictedFileAccessConfig.Enable = true
	cfg.RestrictedFileAccessConfig.Mode = mode
	cfg.RestrictedFileAccessConfig.Target = "host"
	cfg.RestrictedFileAccessConfig.Allow = whitelist.Files.Allow
	cfg.RestrictedFileAccessConfig.Deny = []string{}
	cfg.RestrictedProcessConfig.Enable = true
	cfg.RestrictedProcessConfig.Mode = mode
	cfg.RestrictedProcessConfig.Target = "host"
	cfg.RestrictedProcessConfig.Allow = whitelist.Process.Allow
	cfg.RestrictedMountConfig.Enable = true
	cfg.RestrictedMountConfig.Mode = mode
	cfg.RestrictedMountConfig.Target = "host"
	cfg.RestrictedMountConfig.DenySourcePath = []string{}
	return *cfg
}

// MarshalConfigYAML serializes a WhitelistModel as a YAML configuration file.
func MarshalConfigYAML(whitelist model.WhitelistModel, mode string) ([]byte, error) {
	cfg := BuildConfig(whitelist, mode)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return yaml.Marshal(&cfg)
}

// MarshalReportJSON serializes a WhitelistModel as a JSON report.
func MarshalReportJSON(whitelist model.WhitelistModel) ([]byte, error) {
	if !utf8.ValidString(whitelist.Metadata.Hostname) {
		return nil, fmt.Errorf("metadata.hostname is not UTF-8")
	}
	for _, group := range []struct {
		name   string
		values []string
	}{
		{"network.cidr_allow", whitelist.Network.CIDRAllow}, {"files.allow", whitelist.Files.Allow},
		{"process.allow", whitelist.Process.Allow}, {"warnings", whitelist.Warnings},
	} {
		for i, value := range group.values {
			if !utf8.ValidString(value) {
				return nil, fmt.Errorf("%s[%d] is not UTF-8", group.name, i)
			}
		}
	}
	for i, account := range whitelist.Accounts {
		if !utf8.ValidString(account.Username) || !utf8.ValidString(account.HomeDir) || !utf8.ValidString(account.Shell) {
			return nil, fmt.Errorf("accounts[%d] contains non-UTF-8 text", i)
		}
	}
	return json.MarshalIndent(whitelist, "", "  ")
}

// WriteFile writes data to the specified file path.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
