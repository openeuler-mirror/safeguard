package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
