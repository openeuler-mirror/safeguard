package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_ReturnsErrorForMissingFile(t *testing.T) {
	_, err := NewConfig("/nonexistent/config.yaml")
	require.Error(t, err)
}

func TestNewConfig_ReturnsErrorForInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{invalid yaml: ["), 0o644))

	_, err := NewConfig(path)
	require.Error(t, err)
}

func TestValidate_PassesWhenDNSProxyDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSProxyConfig.Enable = false
	cfg.DNSProxyConfig.Upstreams = []string{}

	assert.NoError(t, cfg.Validate())
}

func TestDefaultConfig_CIDRDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, []string{"0.0.0.0/0", "::/0"}, cfg.RestrictedNetworkConfig.CIDR.Allow)
	assert.Equal(t, []string{}, cfg.RestrictedNetworkConfig.CIDR.Deny)
}

func TestNewConfig_RejectsNullDocument(t *testing.T) {
	for _, content := range []string{"null\n", "~\n", "---\n"} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "null.yaml")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			cfg, err := NewConfig(path)
			require.Error(t, err)
			assert.Nil(t, cfg)
		})
	}
}

func TestValidate_RejectsNilConfig(t *testing.T) {
	var cfg *Config
	require.EqualError(t, cfg.Validate(), "configuration must not be null")
}

func TestNewConfig_RejectsTrailingDocuments(t *testing.T) {
	for _, suffix := range []string{
		"---\npolicy: whitelist\n", "---\nnull\n", "---\n", "---\n[broken\n",
	} {
		t.Run(suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "multiple.yaml")
			require.NoError(t, os.WriteFile(path, []byte("policy: blacklist\n"+suffix), 0o600))
			cfg, err := NewConfig(path)
			require.Error(t, err)
			assert.Nil(t, cfg)
		})
	}
}

func TestNewConfig_AcceptsTrailingComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "single.yaml")
	require.NoError(t, os.WriteFile(path, []byte("policy: whitelist\n# trailing comment\n"), 0o600))
	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "whitelist", cfg.Policy)
}

func TestValidate_RejectsUnknownPolicy(t *testing.T) {
	for _, policy := range []string{"", "white-list", "WHITELIST", " whitelist "} {
		t.Run(policy, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Policy = policy
			require.ErrorContains(t, cfg.Validate(), "policy")
		})
	}
}

func TestNewConfig_ValidatesPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	for _, policy := range []string{"blacklist", "whitelist", "typo"} {
		require.NoError(t, os.WriteFile(path, []byte("policy: "+policy+"\n"), 0o600))
		cfg, err := NewConfig(path)
		if policy == "typo" {
			require.ErrorContains(t, err, "policy")
			assert.Nil(t, cfg)
		} else {
			require.NoError(t, err)
			assert.Equal(t, policy, cfg.Policy)
		}
	}
}

func TestNewConfig_ValidatesEnabledModuleSettings(t *testing.T) {
	for _, module := range []string{"network", "files", "mount", "process"} {
		for _, tc := range []struct {
			mode, target     string
			enabled, invalid bool
		}{
			{"monitor", "host", true, false},
			{"block", "container", true, false},
			{"blok", "host", true, true},
			{"monitor", "containers", true, true},
			{"unused", "unused", false, false},
		} {
			t.Run(module+"/"+tc.mode+"/"+tc.target, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "module.yaml")
				content := fmt.Sprintf("%s:\n  enable: %t\n  mode: %s\n  target: %s\n", module, tc.enabled, tc.mode, tc.target)
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				cfg, err := NewConfig(path)
				if tc.invalid {
					require.ErrorContains(t, err, module+".")
					assert.Nil(t, cfg)
				} else {
					require.NoError(t, err)
					assert.NotNil(t, cfg)
				}
			})
		}
	}
}

func TestNewConfig_RejectsNetworkIDOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("YAML uint decoding already rejects these values on 32-bit hosts")
	}
	for _, kind := range []string{"uid", "gid"} {
		for _, list := range []string{"allow", "deny"} {
			t.Run(kind+"/"+list, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "ids.yaml")
				for _, value := range []string{"4294967295", "4294967296", "18446744073709551615"} {
					content := fmt.Sprintf("network:\n  enable: true\n  %s:\n    %s: [%s]\n", kind, list, value)
					require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
					cfg, err := NewConfig(path)
					if value == "4294967295" {
						require.NoError(t, err)
						assert.NotNil(t, cfg)
					} else {
						require.ErrorContains(t, err, "network."+kind+"."+list+"[0]")
						assert.Nil(t, cfg)
					}
				}
			})
		}
	}
}

func TestNewConfig_ValidatesNetworkCIDRs(t *testing.T) {
	for _, list := range []string{"allow", "deny"} {
		for _, tc := range []struct {
			cidr             string
			enabled, invalid bool
		}{
			{"0.0.0.0/0", true, false}, {"2001:db8::/32", true, false},
			{"192.0.2.1/33", true, true}, {"2001:db8::/129", true, true},
			{"", true, true}, {"not-a-cidr", true, true},
			{"unused", false, false},
		} {
			t.Run(list+"/"+tc.cidr, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "cidr.yaml")
				content := fmt.Sprintf("network:\n  enable: %t\n  cidr:\n    %s: [127.0.0.1/32, %q]\n", tc.enabled, list, tc.cidr)
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				cfg, err := NewConfig(path)
				if tc.invalid {
					require.ErrorContains(t, err, "network.cidr."+list+"[1]")
					assert.Nil(t, cfg)
				} else {
					require.NoError(t, err)
					assert.NotNil(t, cfg)
				}
			})
		}
	}
}

func TestNewConfig_RejectsEmptyDomainRules(t *testing.T) {
	for _, list := range []string{"allow", "deny"} {
		for _, domain := range []string{"", " \t", "example.com", "EXAMPLE.com."} {
			t.Run(list+"/"+domain, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "domain.yaml")
				content := fmt.Sprintf("network:\n  enable: true\n  domain:\n    %s: [example.org, %q]\n", list, domain)
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				cfg, err := NewConfig(path)
				if domain == "" || domain == " \t" {
					require.ErrorContains(t, err, "network.domain."+list+"[1]")
					assert.Nil(t, cfg)
				} else {
					require.NoError(t, err)
					assert.NotNil(t, cfg)
				}
			})
		}
	}
}

func TestNewConfig_ValidatesLogRotationLimits(t *testing.T) {
	for _, field := range []string{"max_size", "max_age"} {
		for _, value := range []int{-1, 0, 100} {
			t.Run(fmt.Sprintf("%s/%d", field, value), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "log.yaml")
				content := fmt.Sprintf("log:\n  %s: %d\n", field, value)
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				cfg, err := NewConfig(path)
				if value < 0 {
					require.ErrorContains(t, err, "log."+field)
					assert.Nil(t, cfg)
				} else {
					require.NoError(t, err)
					assert.NotNil(t, cfg)
				}
			})
		}
	}
}

func TestNewConfig_RejectsUnknownAndDuplicateFields(t *testing.T) {
	for name, content := range map[string]string{
		"unknown root":             "netwrok: {enable: true}\n",
		"unknown nested":           "network: {enbale: true}\n",
		"unsupported process deny": "process: {deny: [sh]}\n",
		"duplicate policy":         "policy: blacklist\npolicy: whitelist\n",
		"duplicate module":         "network: {enable: true}\nnetwork: {enable: false}\n",
		"duplicate nested":         "network:\n  mode: monitor\n  mode: block\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "strict.yaml")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			cfg, err := NewConfig(path)
			require.Error(t, err)
			assert.Nil(t, cfg)
		})
	}
}

func TestNewConfig_StrictModePreservesYAMLMerges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "merge.yaml")
	content := "network: &settings\n  mode: monitor\n  target: host\nfiles:\n  <<: *settings\n  enable: true\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := NewConfig(path)
	require.NoError(t, err)
	assert.True(t, cfg.RestrictedFileAccessConfig.Enable)
	assert.Equal(t, "monitor", cfg.RestrictedFileAccessConfig.Mode)
	assert.Equal(t, []string{"/"}, cfg.RestrictedFileAccessConfig.Allow)
}

func TestNewConfig_ErrorsIdentifySourceAndStage(t *testing.T) {
	for stage, content := range map[string]string{
		"decode configuration":          "unknown_field: true\n",
		"validate configuration":        "policy: typo\n",
		"decode trailing configuration": "policy: blacklist\n---\n[broken\n",
		"exactly one YAML document":     "policy: blacklist\n---\npolicy: whitelist\n",
	} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source.yaml")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			cfg, err := NewConfig(path)
			require.ErrorContains(t, err, stage)
			assert.ErrorContains(t, err, path)
			assert.Nil(t, cfg)
		})
	}
}

func TestNewConfig_OpenErrorPreservesCause(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	cfg, err := NewConfig(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.ErrorContains(t, err, "open configuration")
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	assert.Equal(t, path, pathErr.Path)
	assert.Nil(t, cfg)
}

func TestFilePathsRejectUnrepresentableNames(t *testing.T) {
	for _, list := range []string{"allow", "deny"} {
		for _, value := range []string{"", "relative/path", "/valid\x00suffix", "/", "/tmp/中文"} {
			cfg := DefaultConfig()
			cfg.RestrictedFileAccessConfig.Enable = true
			if list == "allow" {
				cfg.RestrictedFileAccessConfig.Allow = []string{"/valid", value}
			} else {
				cfg.RestrictedFileAccessConfig.Deny = []string{"/valid", value}
			}
			err := cfg.Validate()
			if !strings.HasPrefix(value, "/") || strings.ContainsRune(value, 0) {
				require.ErrorContains(t, err, "files."+list+"[1]")
			} else {
				require.NoError(t, err)
			}
			cfg.RestrictedFileAccessConfig.Enable = false
			require.NoError(t, cfg.Validate())
		}
	}
}

func TestMountSourceNames(t *testing.T) {
	for _, source := range []string{"", " \t", "/dev/sda\x00suffix", "/dev/sda1", "tmpfs", "server:/export"} {
		cfg := DefaultConfig()
		cfg.RestrictedMountConfig.Enable = true
		cfg.RestrictedMountConfig.DenySourcePath = []string{"/dev/valid", source}
		if strings.TrimSpace(source) == "" || strings.ContainsRune(source, 0) {
			require.ErrorContains(t, cfg.Validate(), "mount.deny[1]")
		} else {
			require.NoError(t, cfg.Validate())
		}
		cfg.RestrictedMountConfig.Enable = false
		require.NoError(t, cfg.Validate())
	}
}

func TestProcessRulesMustFitKernelComm(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", false}, {strings.Repeat("a", 15), true}, {strings.Repeat("a", 16), false},
		{strings.Repeat("中", 5), true}, {strings.Repeat("中", 6), false}, {"sh\x00suffix", false},
	} {
		cfg := DefaultConfig()
		cfg.RestrictedProcessConfig.Enable = true
		cfg.RestrictedProcessConfig.Allow = []string{"sh", tc.value}
		if tc.valid {
			require.NoError(t, cfg.Validate())
		} else {
			require.ErrorContains(t, cfg.Validate(), "process.allow[1]")
		}
		cfg.RestrictedProcessConfig.Enable = false
		require.NoError(t, cfg.Validate())
	}
	cfg := DefaultConfig()
	cfg.RestrictedProcessConfig.Enable = true
	cfg.RestrictedProcessConfig.Allow = []string{"sh", "sh"}
	require.NoError(t, cfg.Validate())
}

func TestNetworkCommandsMustFitKernelComm(t *testing.T) {
	for _, list := range []string{"allow", "deny"} {
		for _, tc := range []struct {
			value string
			valid bool
		}{
			{"", false}, {strings.Repeat("x", 15), true}, {strings.Repeat("x", 16), false},
			{strings.Repeat("中", 5), true}, {strings.Repeat("中", 6), false}, {"sh\x00suffix", false},
		} {
			cfg := DefaultConfig()
			cfg.RestrictedNetworkConfig.Enable = true
			if list == "allow" {
				cfg.RestrictedNetworkConfig.Command.Allow = []string{"sh", tc.value}
			} else {
				cfg.RestrictedNetworkConfig.Command.Deny = []string{"sh", tc.value}
			}
			if tc.valid {
				require.NoError(t, cfg.Validate())
			} else {
				require.ErrorContains(t, cfg.Validate(), "network.command."+list+"[1]")
			}
			cfg.RestrictedNetworkConfig.Enable = false
			require.NoError(t, cfg.Validate())
		}
	}
}

func TestFileMapCapacityCountsUniqueRules(t *testing.T) {
	for _, list := range []string{"allow", "deny"} {
		cfg := DefaultConfig()
		cfg.RestrictedFileAccessConfig.Enable = true
		values := make([]string, 256)
		for i := range values {
			values[i] = fmt.Sprintf("/path/%d", i)
		}
		set := func(paths []string) {
			if list == "allow" {
				cfg.RestrictedFileAccessConfig.Allow = paths
			} else {
				cfg.RestrictedFileAccessConfig.Deny = paths
			}
		}
		set(values)
		require.NoError(t, cfg.Validate())
		set(append(append([]string{}, values...), values...))
		require.NoError(t, cfg.Validate())
		set(append(values, "/overflow"))
		require.ErrorContains(t, cfg.Validate(), "files."+list)
	}
	input := []string{"/b", "/a", "/b"}
	unique := UniqueStrings(input)
	require.Equal(t, []string{"/b", "/a"}, unique)
	unique[0] = "changed"
	require.Equal(t, []string{"/b", "/a", "/b"}, input)
}

func TestMountMapCapacity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RestrictedMountConfig.Enable = true
	sources := make([]string, 256)
	for i := range sources {
		sources[i] = fmt.Sprintf("/dev/device-%d", i)
	}
	cfg.RestrictedMountConfig.DenySourcePath = sources
	require.NoError(t, cfg.Validate())
	cfg.RestrictedMountConfig.DenySourcePath = append(append([]string{}, sources...), sources...)
	require.NoError(t, cfg.Validate())
	cfg.RestrictedMountConfig.DenySourcePath = append(sources, "/dev/overflow")
	require.ErrorContains(t, cfg.Validate(), "mount.deny")
	cfg.RestrictedMountConfig.Enable = false
	require.NoError(t, cfg.Validate())
}

func TestNetworkIDMapCapacitiesAreIndependent(t *testing.T) {
	for _, field := range []string{"uid.allow", "uid.deny", "gid.allow", "gid.deny"} {
		cfg := DefaultConfig()
		cfg.RestrictedNetworkConfig.Enable = true
		ids := make([]uint, 256)
		for i := range ids {
			ids[i] = uint(i)
		}
		cfg.RestrictedNetworkConfig.UID = UIDConfig{Allow: ids, Deny: ids}
		cfg.RestrictedNetworkConfig.GID = GIDConfig{Allow: ids, Deny: ids}
		require.NoError(t, cfg.Validate())
		var target *[]uint
		switch field {
		case "uid.allow":
			target = &cfg.RestrictedNetworkConfig.UID.Allow
		case "uid.deny":
			target = &cfg.RestrictedNetworkConfig.UID.Deny
		case "gid.allow":
			target = &cfg.RestrictedNetworkConfig.GID.Allow
		case "gid.deny":
			target = &cfg.RestrictedNetworkConfig.GID.Deny
		}
		*target = append(append([]uint{}, ids...), ids...)
		require.NoError(t, cfg.Validate())
		*target = append(*target, 256)
		require.ErrorContains(t, cfg.Validate(), "network."+field)
		cfg.RestrictedNetworkConfig.Enable = false
		require.NoError(t, cfg.Validate())
	}
}

func TestCIDRCapacityPerDirectionAndFamily(t *testing.T) {
	prefixes := make([]string, 0, 512)
	for i := 0; i < 256; i++ {
		prefixes = append(prefixes, fmt.Sprintf("10.0.%d.0/24", i), fmt.Sprintf("2001:db8:%x::/48", i))
	}
	for _, direction := range []string{"allow", "deny"} {
		for _, family := range []string{"IPv4", "IPv6"} {
			cfg := DefaultConfig()
			cfg.RestrictedNetworkConfig.Enable = true
			cfg.RestrictedNetworkConfig.CIDR = CIDRConfig{Allow: prefixes, Deny: prefixes}
			require.NoError(t, cfg.Validate())
			target := &cfg.RestrictedNetworkConfig.CIDR.Allow
			if direction == "deny" {
				target = &cfg.RestrictedNetworkConfig.CIDR.Deny
			}
			*target = append(append([]string{}, prefixes...), "10.0.0.123/24", "2001:db8::123/48")
			require.NoError(t, cfg.Validate())
			overflow := "10.1.0.0/24"
			if family == "IPv6" {
				overflow = "2001:db8:100::/48"
			}
			*target = append(*target, overflow)
			err := cfg.Validate()
			require.ErrorContains(t, err, "network.cidr."+direction)
			require.ErrorContains(t, err, family)
		}
	}
}

func TestProcessMapCapacityUsesRepresentableUniqueNames(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RestrictedProcessConfig.Enable = true
	require.NoError(t, cfg.Validate())
	names := make([]string, 1024)
	for i := range names {
		names[i] = fmt.Sprintf("proc%04d", i)
	}
	cfg.RestrictedProcessConfig.Allow = names
	require.NoError(t, cfg.Validate())
	cfg.RestrictedProcessConfig.Allow = append(append([]string{}, names...), names...)
	require.NoError(t, cfg.Validate())
	cfg.RestrictedProcessConfig.Allow = append(names, "overflow")
	require.ErrorContains(t, cfg.Validate(), "process.allow")
	require.ErrorContains(t, cfg.Validate(), "1024")
	cfg.RestrictedProcessConfig.Enable = false
	require.NoError(t, cfg.Validate())
}

func TestLegacyFileDenyEncodingRetainsPathValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RestrictedFileAccessConfig.Enable = true
	cfg.RestrictedFileAccessConfig.Deny = []string{"|/home/1|/home/2|/test"}
	require.NoError(t, cfg.Validate())
	require.Equal(t, "|/home/1|/home/2|/test", cfg.RestrictedFileAccessConfig.Deny[0])
	for _, value := range []string{"|relative|/valid", "|/valid|relative", "|/valid|", "|/valid\x00suffix"} {
		cfg.RestrictedFileAccessConfig.Deny = []string{value}
		require.ErrorContains(t, cfg.Validate(), "files.deny[0]")
	}
}

func TestDomainWireBoundaries(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, direction := range []string{"allow", "deny"} {
		for _, tc := range []struct {
			name  string
			valid bool
		}{
			{strings.Repeat("a", 63) + ".com", true}, {strings.Repeat("a", 64) + ".com", false},
			{maxName, true}, {maxName + "d", false}, {`a\046b.example`, true},
		} {
			cfg := DefaultConfig()
			cfg.RestrictedNetworkConfig.Enable = true
			if direction == "allow" {
				cfg.Domain.Allow = []string{"valid.example", tc.name}
			} else {
				cfg.Domain.Deny = []string{"valid.example", tc.name}
			}
			if tc.valid {
				require.NoError(t, cfg.Validate())
			} else {
				require.ErrorContains(t, cfg.Validate(), "network.domain."+direction+"[1]")
			}
		}
	}
}

func TestPathMatchingWidths(t *testing.T) {
	for _, field := range []string{"files.allow", "files.deny", "mount.deny"} {
		limit := 79
		if field == "mount.deny" {
			limit = 63
		}
		for _, size := range []int{limit, limit + 1} {
			cfg := DefaultConfig()
			cfg.RestrictedFileAccessConfig.Enable = true
			cfg.RestrictedMountConfig.Enable = true
			value := "/" + strings.Repeat("p", size-1)
			switch field {
			case "files.allow":
				cfg.RestrictedFileAccessConfig.Allow = []string{value}
			case "files.deny":
				cfg.RestrictedFileAccessConfig.Deny = []string{value}
			case "mount.deny":
				cfg.RestrictedMountConfig.DenySourcePath = []string{value}
			}
			if size == limit {
				require.NoError(t, cfg.Validate())
			} else {
				require.ErrorContains(t, cfg.Validate(), field+"[0]")
			}
		}
	}
	cfg := DefaultConfig()
	cfg.RestrictedMountConfig.Enable = true
	cfg.RestrictedMountConfig.DenySourcePath = []string{strings.Repeat("a", 40) + "|" + strings.Repeat("b", 39)}
	require.ErrorContains(t, cfg.Validate(), "mount.deny[0]")
}

func TestRotationArithmeticBounds(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int64 megabyte boundary requires a 64-bit int")
	}
	for _, limit := range []struct {
		field string
		max   int64
	}{
		{"max_size", (1<<63 - 1) / (1024 * 1024)}, {"max_age", (1<<63 - 1) / (24 * 60 * 60 * 1000000000)},
	} {
		cfg := DefaultConfig()
		set := func(value int64) {
			if limit.field == "max_size" {
				cfg.Log.MaxSize = int(value)
			} else {
				cfg.Log.MaxAge = int(value)
			}
		}
		set(limit.max)
		require.NoError(t, cfg.Validate())
		set(limit.max + 1)
		require.ErrorContains(t, cfg.Validate(), "log."+limit.field)
		set(0)
		require.NoError(t, cfg.Validate())
	}
}
