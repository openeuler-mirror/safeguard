package render

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"culinux/pkg/config"
	"culinux/pkg/controller/model"

	"gopkg.in/yaml.v2"
)

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
	// Refuse to follow a symlink planted at `path`. Without this, a
	// low-privilege user who can write the parent directory could
	// pre-create `path` as a symlink to (e.g.) /etc/shadow and trick
	// the root-run controller into overwriting the target.
	if fi, err := os.Lstat(path); err == nil && (fi.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("refusing to write: %s is a symlink", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
