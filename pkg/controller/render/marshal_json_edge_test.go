package render

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"culinux/pkg/controller/model"
)

func TestMarshalReportJSON_ValidJSON(t *testing.T) {
	w := model.WhitelistModel{}
	data, err := MarshalReportJSON(w)
	assert.NoError(t, err)
	var parsed map[string]interface{}
	assert.NoError(t, json.Unmarshal(data, &parsed))
}
