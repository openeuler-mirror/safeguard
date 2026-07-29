package render

import (
	"testing"

	"culinux/pkg/controller/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalConfigYAML_EmptyWhitelistProducesValidYAML(t *testing.T) {
	data, err := MarshalConfigYAML(model.WhitelistModel{}, "monitor")
	require.NoError(t, err)
	assert.Contains(t, string(data), "policy: whitelist")
	assert.Contains(t, string(data), "mode: monitor")
}
