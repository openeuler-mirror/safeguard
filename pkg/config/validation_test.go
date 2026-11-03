package config

import (
	"os"
	"path/filepath"
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
