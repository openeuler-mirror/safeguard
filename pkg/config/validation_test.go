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
