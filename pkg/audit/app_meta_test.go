package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewApp_HasExpectedName(t *testing.T) {
	app := NewApp("dev")
	assert.Equal(t, "safeguard", app.Name)
}

func TestNewApp_HasVersion(t *testing.T) {
	app := NewApp("dev")
	assert.NotEmpty(t, app.Version)
}

func TestNewApp_HasConfigFlag(t *testing.T) {
	app := NewApp("dev")
	flagNames := []string{}
	for _, flag := range app.Flags {
		flagNames = append(flagNames, flag.Names()[0])
	}
	assert.Contains(t, flagNames, "config")
}
