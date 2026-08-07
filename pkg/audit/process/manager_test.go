//go:build integration
// +build integration

package process

import (
	"testing"

	"culinux/pkg/config"

	"github.com/stretchr/testify/assert"
)

func Test_Attach(t *testing.T) {
	t.Run("attaches the BPF program", func(t *testing.T) {
		config := config.DefaultConfig()
		mgr := createManager(config)
		defer mgr.mod.Close()

		actual := mgr.Attach()
		assert.Equal(t, nil, actual)
	})
}

func createManager(conf *config.Config) Manager {
	mod, err := setupBPFProgram()
	if err != nil {
		panic(err)
	}

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	err = mgr.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return mgr
}
