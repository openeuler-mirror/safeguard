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
