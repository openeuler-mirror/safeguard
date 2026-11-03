package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// RestrictedNetworkConfig holds network restriction settings.
type RestrictedNetworkConfig struct {
	Enable  bool          `yaml:"enable"`
	Mode    string        `yaml:"mode"`
	Target  string        `yaml:"target"`
	Command CommandConfig `yaml:"command"`
	CIDR    CIDRConfig    `yaml:"cidr"`
	Domain  DomainConfig  `yaml:"domain"`
	UID     UIDConfig     `yaml:"uid"`
	GID     GIDConfig     `yaml:"gid"`
}

// RestrictedFileAccessConfig holds file access restriction settings.
type RestrictedFileAccessConfig struct {
	Enable bool     `yaml:"enable"`
	Mode   string   `yaml:"mode"`
	Target string   `yaml:"target"`
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
}

// RestrictedMountConfig holds mount restriction settings.
type RestrictedMountConfig struct {
	Enable         bool     `yaml:"enable"`
	Mode           string   `yaml:"mode"`
	Target         string   `yaml:"target"`
	DenySourcePath []string `yaml:"deny"`
}

// RestrictedProcessConfig holds process restriction settings.
type RestrictedProcessConfig struct {
	Enable bool     `yaml:"enable"`
	Mode   string   `yaml:"mode"`
	Target string   `yaml:"target"`
	Allow  []string `yaml:"allow"`
}

// DomainConfig holds domain allow and deny lists.
type DomainConfig struct {
	Allow    []string `yaml:"allow"`
	Deny     []string `yaml:"deny"`
	Interval uint     `yaml:"interval"` // deprecated
}

// DNSProxyConfig holds DNS proxy settings.
type DNSProxyConfig struct {
	Enable        bool     `yaml:"enable"`
	Upstreams     []string `yaml:"upstreams"`
	BindAddresses []string `yaml:"bind"`
}

// CIDRConfig holds CIDR allow and deny lists.
type CIDRConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// CommandConfig holds command allow and deny lists.
type CommandConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// UIDConfig holds UID allow and deny lists.
type UIDConfig struct {
	Allow []uint `yaml:"allow"`
	Deny  []uint `yaml:"deny"`
}

// GIDConfig holds GID allow and deny lists.
type GIDConfig struct {
	Allow []uint `yaml:"allow"`
	Deny  []uint `yaml:"deny"`
}

// LogConfig holds logging configuration settings.
type LogConfig struct {
	Level   string            `yaml:"level"`
	Format  string            `yaml:"format"`
	Output  string            `yaml:"output"`
	MaxSize int               `yaml:"max_size"`
	MaxAge  int               `yaml:"max_age"`
	Labels  map[string]string `yaml:"labels"`
}

// Config is the top-level safeguard configuration structure.
type Config struct {
	Policy                     string `yaml:"policy"` // blacklist 或 whitelist
	RestrictedNetworkConfig    `yaml:"network"`
	RestrictedFileAccessConfig `yaml:"files"`
	RestrictedMountConfig      `yaml:"mount"`
	RestrictedProcessConfig    `yaml:"process"`
	DNSProxyConfig             `yaml:"dns_proxy"`
	Log                        LogConfig
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Policy: "blacklist", // 默认黑名单模式
		RestrictedNetworkConfig: RestrictedNetworkConfig{
			Enable:  false,
			Mode:    "monitor",
			Target:  "host",
			Command: CommandConfig{Allow: []string{}, Deny: []string{}},
			CIDR:    CIDRConfig{Allow: []string{"0.0.0.0/0", "::/0"}, Deny: []string{}},
			Domain:  DomainConfig{Allow: []string{}, Deny: []string{}, Interval: 5},
			UID:     UIDConfig{Allow: []uint{}, Deny: []uint{}},
			GID:     GIDConfig{Allow: []uint{}, Deny: []uint{}},
		},
		RestrictedFileAccessConfig: RestrictedFileAccessConfig{
			Enable: false,
			Mode:   "monitor",
			Target: "host",
			Allow:  []string{"/"},
			Deny:   []string{},
		},
		RestrictedMountConfig: RestrictedMountConfig{
			Enable:         false,
			Mode:           "monitor",
			Target:         "host",
			DenySourcePath: []string{},
		},
		RestrictedProcessConfig: RestrictedProcessConfig{
			Enable: false,
			Mode:   "monitor",
			Target: "host",
			Allow:  []string{},
		},
		DNSProxyConfig: DNSProxyConfig{
			Enable:        false,
			Upstreams:     []string{},
			BindAddresses: []string{"127.0.0.1", "172.17.0.1"},
		},
		Log: LogConfig{
			Level:  "INFO",
			Format: "json",
			Output: "stdout",
			Labels: map[string]string{},
		},
	}
}

// NewConfig reads and parses a YAML configuration file.
func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("open configuration %q: %w", configPath, err)
	}
	defer file.Close()

	d := yaml.NewDecoder(file)
	d.SetStrict(true)

	config := DefaultConfig()
	if err := d.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode configuration %q: %w", configPath, err)
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("decode trailing configuration document in %q: %w", configPath, err)
		}
		return nil, fmt.Errorf("configuration %q must contain exactly one YAML document", configPath)
	}

	err = config.Validate()
	if err != nil {
		return nil, fmt.Errorf("validate configuration %q: %w", configPath, err)
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("configuration must not be null")
	}
	if c.Policy != "blacklist" && c.Policy != "whitelist" {
		return fmt.Errorf("invalid policy %q: must be blacklist or whitelist", c.Policy)
	}
	for _, module := range []struct {
		name         string
		enabled      bool
		mode, target string
	}{
		{"network", c.RestrictedNetworkConfig.Enable, c.RestrictedNetworkConfig.Mode, c.RestrictedNetworkConfig.Target},
		{"files", c.RestrictedFileAccessConfig.Enable, c.RestrictedFileAccessConfig.Mode, c.RestrictedFileAccessConfig.Target},
		{"mount", c.RestrictedMountConfig.Enable, c.RestrictedMountConfig.Mode, c.RestrictedMountConfig.Target},
		{"process", c.RestrictedProcessConfig.Enable, c.RestrictedProcessConfig.Mode, c.RestrictedProcessConfig.Target},
	} {
		if !module.enabled {
			continue
		}
		if module.mode != "monitor" && module.mode != "block" {
			return fmt.Errorf("invalid %s.mode %q: must be monitor or block", module.name, module.mode)
		}
		if module.target != "host" && module.target != "container" {
			return fmt.Errorf("invalid %s.target %q: must be host or container", module.name, module.target)
		}
	}

	for _, limit := range []struct {
		name  string
		value int
	}{{"max_size", c.Log.MaxSize}, {"max_age", c.Log.MaxAge}} {
		if limit.value < 0 {
			return fmt.Errorf("log.%s must not be negative", limit.name)
		}
	}
	if c.RestrictedFileAccessConfig.Enable {
		for _, list := range []struct {
			name   string
			values []string
		}{
			{"allow", c.RestrictedFileAccessConfig.Allow}, {"deny", c.RestrictedFileAccessConfig.Deny},
		} {
			for i, value := range list.values {
				if !strings.HasPrefix(value, "/") || strings.ContainsRune(value, 0) {
					return fmt.Errorf("files.%s[%d]: path must be absolute and contain no NUL", list.name, i)
				}
			}
		}
	}
	if c.RestrictedMountConfig.Enable {
		for i, source := range c.RestrictedMountConfig.DenySourcePath {
			if strings.TrimSpace(source) == "" || strings.ContainsRune(source, 0) {
				return fmt.Errorf("mount.deny[%d]: source must not be empty or contain NUL", i)
			}
		}
	}
	if c.RestrictedNetworkConfig.Enable {
		if err := c.RestrictedNetworkConfig.validate(); err != nil {
			return err
		}
	}
	if c.DNSProxyConfig.Enable && len(c.DNSProxyConfig.Upstreams) == 0 {
		return errors.New("One or more dns_proxy.upstreams must be specified.")
	}

	return nil
}

func (c RestrictedNetworkConfig) validate() error {
	for _, list := range []struct {
		name   string
		values []string
	}{
		{"allow", c.CIDR.Allow}, {"deny", c.CIDR.Deny},
	} {
		for i, value := range list.values {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return fmt.Errorf("network.cidr.%s[%d]: %w", list.name, i, err)
			}
		}
	}
	for _, list := range []struct {
		name   string
		values []string
	}{
		{"allow", c.Domain.Allow}, {"deny", c.Domain.Deny},
	} {
		for i, value := range list.values {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("network.domain.%s[%d]: domain must not be empty", list.name, i)
			}
		}
	}
	for _, list := range []struct {
		name   string
		values []uint
	}{
		{"uid.allow", c.UID.Allow}, {"uid.deny", c.UID.Deny},
		{"gid.allow", c.GID.Allow}, {"gid.deny", c.GID.Deny},
	} {
		for i, value := range list.values {
			if uint64(value) > 1<<32-1 {
				return fmt.Errorf("network.%s[%d]: %d exceeds uint32", list.name, i, value)
			}
		}
	}
	return nil
}

func (c *Config) EnableDNSProxy() bool {
	return c.DNSProxyConfig.Enable
}

func (c *Config) IsRestrictedMode(target string) bool {
	switch target {
	case "network":
		if c.RestrictedNetworkConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "fileaccess":
		if c.RestrictedFileAccessConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "mount":
		if c.RestrictedMountConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "process":
		if c.RestrictedProcessConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	default:
		return false
	}
}

func (c *Config) IsOnlyContainer(target string) bool {
	switch target {
	case "network":
		if c.RestrictedNetworkConfig.Target == "container" {
			return true
		} else {
			return false
		}
	case "fileaccess":
		if c.RestrictedFileAccessConfig.Target == "container" {
			return true
		} else {
			return false
		}
	case "mount":
		if c.RestrictedMountConfig.Target == "container" {
			return true
		} else {
			return false
		}
	case "process":
		if c.RestrictedProcessConfig.Target == "container" {
			return true
		} else {
			return false
		}
	default:
		return false
	}
}
