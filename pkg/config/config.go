package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
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

	if config.RestrictedNetworkConfig.Enable {
		config.Domain.Allow = NormalizeDomains(config.Domain.Allow)
		config.Domain.Deny = NormalizeDomains(config.Domain.Deny)
		config.UID.Allow = NormalizeIDs(config.UID.Allow)
		config.UID.Deny = NormalizeIDs(config.UID.Deny)
		config.GID.Allow = NormalizeIDs(config.GID.Allow)
		config.GID.Deny = NormalizeIDs(config.GID.Deny)
		for _, list := range []struct {
			name   string
			values *[]string
		}{
			{"allow", &config.RestrictedNetworkConfig.CIDR.Allow}, {"deny", &config.RestrictedNetworkConfig.CIDR.Deny},
		} {
			normalized, err := NormalizeCIDRs(*list.values)
			if err != nil {
				return nil, fmt.Errorf("normalize configuration %q network.cidr.%s: %w", configPath, list.name, err)
			}
			*list.values = normalized
		}
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
		name    string
		value   int
		maximum int64
	}{{"max_size", c.Log.MaxSize, (1<<63 - 1) / (1024 * 1024)}, {"max_age", c.Log.MaxAge, (1<<63 - 1) / int64(24*time.Hour)}} {
		if limit.value < 0 {
			return fmt.Errorf("log.%s must not be negative", limit.name)
		}
		if int64(limit.value) > limit.maximum {
			return fmt.Errorf("log.%s exceeds arithmetic limit %d", limit.name, limit.maximum)
		}
	}
	if c.RestrictedFileAccessConfig.Enable {
		for _, list := range []struct {
			name   string
			values []string
		}{
			{"allow", c.RestrictedFileAccessConfig.Allow}, {"deny", c.RestrictedFileAccessConfig.Deny},
		} {
			if count := len(UniqueStrings(list.values)); count > 256 {
				return fmt.Errorf("files.%s: %d unique paths exceed map capacity 256", list.name, count)
			}
			for i, value := range list.values {
				// LOOP_NAME=80 requires the terminating NUL inside the comparison range.
				if len(value) > 79 {
					return fmt.Errorf("files.%s[%d]: encoded path exceeds 79 bytes", list.name, i)
				}
				paths := []string{value}
				// Preserve the legacy kernel's leading-pipe deny encoding.
				if list.name == "deny" && strings.HasPrefix(value, "|") {
					paths = strings.Split(value[1:], "|")
				}
				for _, path := range paths {
					if !strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) {
						return fmt.Errorf("files.%s[%d]: path must be absolute and contain no NUL", list.name, i)
					}
				}
			}
		}
	}
	if c.RestrictedMountConfig.Enable {
		if count := len(UniqueStrings(c.RestrictedMountConfig.DenySourcePath)); count > 256 {
			return fmt.Errorf("mount.deny: %d unique sources exceed map capacity 256", count)
		}
		for i, source := range c.RestrictedMountConfig.DenySourcePath {
			if len(source) > 79 {
				return fmt.Errorf("mount.deny[%d]: encoded source exceeds 79 bytes", i)
			}
			for _, part := range strings.Split(source, "|") {
				if len(part) > 63 {
					return fmt.Errorf("mount.deny[%d]: source exceeds DEV_LEN-1 (63 bytes)", i)
				}
			}
			if strings.TrimSpace(source) == "" || strings.ContainsRune(source, 0) {
				return fmt.Errorf("mount.deny[%d]: source must not be empty or contain NUL", i)
			}
		}
	}
	if c.RestrictedProcessConfig.Enable {
		if count := len(UniqueStrings(c.RestrictedProcessConfig.Allow)); count > 1024 {
			return fmt.Errorf("process.allow: %d unique names exceed map capacity 1024", count)
		}
		if err := validateCommRules("process.allow", c.RestrictedProcessConfig.Allow); err != nil {
			return err
		}
	}
	if c.RestrictedNetworkConfig.Enable {
		if err := c.RestrictedNetworkConfig.validate(); err != nil {
			return err
		}
	}
	if c.DNSProxyConfig.Enable {
		if len(c.DNSProxyConfig.BindAddresses) == 0 {
			return errors.New("dns_proxy.bind must contain at least one listener")
		}
		seen := map[string]bool{}
		wildcard, ipv4Count := false, 0
		for i, address := range c.DNSProxyConfig.BindAddresses {
			if strings.TrimSpace(address) == "" {
				return fmt.Errorf("dns_proxy.bind[%d]: listener must not be empty", i)
			}
			key := dnsListenerKey(address)
			if seen[key] {
				return fmt.Errorf("dns_proxy.bind[%d]: duplicate listener %q", i, address)
			}
			seen[key] = true
			if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
				ipv4Count++
				if ip.IsUnspecified() {
					wildcard = true
				}
			}
		}
		if wildcard && ipv4Count > 1 {
			return errors.New("dns_proxy.bind: IPv4 wildcard conflicts with specific listeners")
		}
	}
	if c.DNSProxyConfig.Enable {
		for i, server := range c.DNSProxyConfig.Upstreams {
			if ip := net.ParseIP(server); ip != nil {
				if ip.IsUnspecified() {
					return fmt.Errorf("dns_proxy.upstreams[%d]: address must not be unspecified", i)
				}
				continue
			}
			_, valid := dns.IsDomainName(server)
			if server == "" || !valid || strings.ContainsAny(server, ":/[] \t\r\n\x00\\") {
				return fmt.Errorf("dns_proxy.upstreams[%d]: expected IP or hostname without port (uses 53)", i)
			}
		}
	}
	if c.DNSProxyConfig.Enable {
		for i, server := range c.DNSProxyConfig.Upstreams {
			for _, bind := range c.DNSProxyConfig.BindAddresses {
				ip := net.ParseIP(server)
				if dnsListenerKey(server) == dnsListenerKey(bind) || bind == "0.0.0.0" && ip != nil && ip.To4() != nil && ip.IsLoopback() {
					return fmt.Errorf("dns_proxy.upstreams[%d]: upstream points to proxy listener", i)
				}
			}
		}
	}
	if c.DNSProxyConfig.Enable && len(c.DNSProxyConfig.Upstreams) == 0 {
		return errors.New("One or more dns_proxy.upstreams must be specified.")
	}
	if c.DNSProxyConfig.Enable && !c.RestrictedNetworkConfig.Enable {
		return errors.New("dns_proxy.enable requires network.enable: proxy rules use network maps")
	}

	return nil
}

func (c RestrictedNetworkConfig) validate() error {
	for _, list := range []struct {
		name   string
		values []string
	}{
		{"allow", c.Command.Allow}, {"deny", c.Command.Deny},
	} {
		if err := validateCommRules("network.command."+list.name, list.values); err != nil {
			return err
		}
	}

	for _, list := range []struct {
		name   string
		values []string
	}{
		{"allow", c.CIDR.Allow}, {"deny", c.CIDR.Deny},
	} {
		prefixes := map[string]map[string]bool{"IPv4": {}, "IPv6": {}}
		for i, value := range list.values {
			_, prefix, err := net.ParseCIDR(value)
			if err != nil {
				return fmt.Errorf("network.cidr.%s[%d]: %w", list.name, i, err)
			}
			family := "IPv6"
			if prefix.IP.To4() != nil {
				family = "IPv4"
			}
			prefixes[family][prefix.String()] = true
			if len(prefixes[family]) > 256 {
				return fmt.Errorf("network.cidr.%s[%d]: %s map capacity 256 exceeded", list.name, i, family)
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
			var wire [255]byte
			size, err := dns.PackDomainName(dns.Fqdn(value), wire[:], 0, nil, false)
			if err == nil && size > len(wire) {
				err = dns.ErrLongDomain
			}
			if err != nil {
				return fmt.Errorf("network.domain.%s[%d]: invalid DNS wire name: %w", list.name, i, err)
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
		unique := make(map[uint]struct{}, len(list.values))
		for i, value := range list.values {
			if uint64(value) > 1<<32-1 {
				return fmt.Errorf("network.%s[%d]: %d exceeds uint32", list.name, i, value)
			}
			unique[value] = struct{}{}
		}
		if len(unique) > 256 {
			return fmt.Errorf("network.%s: %d unique IDs exceed map capacity 256", list.name, len(unique))
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

// Kernel comm keys contain at most 15 bytes plus a terminating NUL.
func validateCommRules(field string, values []string) error {
	for i, value := range values {
		if len(value) == 0 || len(value) > 15 || strings.ContainsRune(value, 0) {
			return fmt.Errorf("%s[%d]: name must contain 1–15 bytes and no NUL (got %d bytes)", field, i, len(value))
		}
	}
	return nil
}

// UniqueStrings preserves first-seen order and does not modify the input slice.
func UniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func dnsListenerKey(address string) string {
	if ip := net.ParseIP(address); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSuffix(address, "."))
}
