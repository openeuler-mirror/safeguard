package render

import (
	"encoding/json"
	"os"
	"path/filepath"

	"culinux/pkg/config"
	"culinux/pkg/controller/model"

	"gopkg.in/yaml.v2"
)

func BuildConfig(whitelist model.WhitelistModel, mode string) config.Config {
	cfg := config.DefaultConfig()
	cfg.Policy = "whitelist"
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
	cfg.RestrictedProcessConfig.Mode = "monitor"
	cfg.RestrictedProcessConfig.Target = "host"
	cfg.RestrictedProcessConfig.Allow = whitelist.Process.Allow
	cfg.RestrictedMountConfig.Enable = true
	cfg.RestrictedMountConfig.Mode = "monitor"
	cfg.RestrictedMountConfig.Target = "host"
	cfg.RestrictedMountConfig.DenySourcePath = []string{}
	return *cfg
}

func MarshalConfigYAML(whitelist model.WhitelistModel, mode string) ([]byte, error) {
	cfg := BuildConfig(whitelist, mode)
	return yaml.Marshal(&cfg)
}

func MarshalReportJSON(whitelist model.WhitelistModel) ([]byte, error) {
	return json.MarshalIndent(whitelist, "", "  ")
}

func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
