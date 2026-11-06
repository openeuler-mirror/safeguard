package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeCIDRsKeepsInputAndOriginalErrorIndex(t *testing.T) {
	input := []string{"192.0.2.129/24", "192.0.2.1/24", "2001:0DB8::123/32", "2001:db8::/32", "::ffff:192.0.2.1/120"}
	before := append([]string{}, input...)
	normalized, err := NormalizeCIDRs(input)
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.0/24", "2001:db8::/32"}, normalized)
	require.Equal(t, before, input)
	normalized[0] = "changed"
	require.Equal(t, before, input)
	input = append(input, "broken")
	_, err = NormalizeCIDRs(input)
	require.ErrorContains(t, err, "[5]")
}

func TestNewConfigNormalizesBothCIDRDirections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prefixes.yaml")
	source := []byte("network:\n  enable: true\n  cidr:\n    allow: [192.0.2.123/24, 192.0.2.0/24]\n    deny: ['2001:db8::123/32', '2001:db8::/32']\n")
	require.NoError(t, os.WriteFile(path, source, 0600))
	cfg, err := NewConfig(path)
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.0/24"}, cfg.RestrictedNetworkConfig.CIDR.Allow)
	require.Equal(t, []string{"2001:db8::/32"}, cfg.RestrictedNetworkConfig.CIDR.Deny)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, source, after)
}

func TestShippedConfigurationsRemainLoadable(t *testing.T) {
	count := 0
	for _, root := range []string{"../../config", "../../testdata"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			ext := filepath.Ext(path)
			if info.IsDir() || (ext != ".yaml" && ext != ".yml") || filepath.Base(path) == "docker-compose.yml" {
				return nil
			}
			count++
			_, loadErr := NewConfig(path)
			require.NoError(t, loadErr, path)
			return nil
		})
		require.NoError(t, err)
	}
	require.Greater(t, count, 0)
}

func TestNormalizeLoadedIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.yaml")
	source := []byte("network:\n  enable: true\n  uid: {allow: [9, 1, 9], deny: [4, 2, 4]}\n  gid: {allow: [8, 0, 8], deny: [7, 3, 7]}\n")
	require.NoError(t, os.WriteFile(path, source, 0600))
	cfg, err := NewConfig(path)
	require.NoError(t, err)
	require.Equal(t, []uint{1, 9}, cfg.UID.Allow)
	require.Equal(t, []uint{2, 4}, cfg.UID.Deny)
	require.Equal(t, []uint{0, 8}, cfg.GID.Allow)
	require.Equal(t, []uint{3, 7}, cfg.GID.Deny)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, source, after)
}

func TestNormalizeIDsPreservesSlice(t *testing.T) {
	input := []uint{9, 1, 9}
	require.Equal(t, []uint{1, 9}, NormalizeIDs(input))
	require.Equal(t, []uint{9, 1, 9}, input)
}

func TestNormalizeLoadedDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.yaml")
	require.NoError(t, os.WriteFile(path, []byte("network:\n  enable: true\n  domain:\n    allow: [Example.COM, example.com.]\n    deny: [Blocked.ORG, blocked.org.]\n"), 0600))
	cfg, err := NewConfig(path)
	require.NoError(t, err)
	require.Equal(t, []string{"example.com."}, cfg.Domain.Allow)
	require.Equal(t, []string{"blocked.org."}, cfg.Domain.Deny)
}

func TestNormalizeDomainsWireNames(t *testing.T) {
	input := []string{"Ä.EXAMPLE", "ä.EXAMPLE", `foo\046BAR.example`, `foo\.bar.EXAMPLE`}
	before := append([]string{}, input...)
	expected := []string{`\195\132.example.`, `\195\164.example.`, `foo\.bar.example.`}
	require.Equal(t, expected, NormalizeDomains(input))
	require.Equal(t, before, input)
	path := filepath.Join(t.TempDir(), "dns.yaml")
	source := "network:\n  enable: true\n  domain:\n    allow:\n      - 'Ä.EXAMPLE'\n      - 'ä.EXAMPLE'\n      - 'foo\\046BAR.example'\n      - 'foo\\.bar.EXAMPLE'\n"
	require.NoError(t, os.WriteFile(path, []byte(source), 0600))
	cfg, err := NewConfig(path)
	require.NoError(t, err)
	require.Equal(t, expected, cfg.Domain.Allow)
}
