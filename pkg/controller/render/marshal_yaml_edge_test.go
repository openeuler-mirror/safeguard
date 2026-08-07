package render

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"culinux/pkg/controller/model"
)

func TestMarshalConfigYAML_ContainsNetwork(t *testing.T) {
	w := model.WhitelistModel{}
	data, err := MarshalConfigYAML(w, "monitor")
	assert.NoError(t, err)
	assert.Contains(t, string(data), "network")
}
