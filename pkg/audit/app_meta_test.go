package audit

import (
	"bytes"
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

func TestNewAppVersion(t *testing.T) {
	for _, version := range []string{"dev", "v1.2.3"} {
		t.Run(version, func(t *testing.T) {
			app := NewApp(version)
			var output bytes.Buffer
			app.Writer = &output
			if err := app.Run([]string{"safeguard", "--version"}); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, version, app.Version)
			assert.Contains(t, output.String(), version)
		})
	}
}
