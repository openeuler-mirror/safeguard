package render

import (
	"os"
	"path/filepath"
	"testing"

	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalReportJSON_EmptyWhitelistProducesValidJSON(t *testing.T) {
	data, err := MarshalReportJSON(model.WhitelistModel{})
	require.NoError(t, err)
	assert.Contains(t, string(data), "\"metadata\"")
	assert.Contains(t, string(data), "\"network\"")
	assert.Contains(t, string(data), "\"files\"")
	assert.Contains(t, string(data), "\"process\"")
}

func TestWriteFile_OverwritesExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output.txt")

	require.NoError(t, WriteFile(path, []byte("first")))
	require.NoError(t, WriteFile(path, []byte("second")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second", string(data))
}

func TestBuildConfig_PropagatesWhitelistContent(t *testing.T) {
	cfg := BuildConfig(model.WhitelistModel{
		Network: model.NetworkWhitelist{
			CIDRAllow: []string{"10.0.0.1/32"},
			UIDAllow:  []uint{100},
			GIDAllow:  []uint{200},
		},
		Files:   model.FileWhitelist{Allow: []string{"/var/log"}},
		Process: model.ProcessWhitelist{Allow: []string{"nginx"}},
	}, "monitor")

	assert.Equal(t, []string{"10.0.0.1/32"}, cfg.RestrictedNetworkConfig.CIDR.Allow)
	assert.Equal(t, []uint{100}, cfg.RestrictedNetworkConfig.UID.Allow)
	assert.Equal(t, []uint{200}, cfg.RestrictedNetworkConfig.GID.Allow)
	assert.Equal(t, []string{"/var/log"}, cfg.RestrictedFileAccessConfig.Allow)
	assert.Equal(t, []string{"nginx"}, cfg.RestrictedProcessConfig.Allow)
}
