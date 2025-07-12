package process

import (
	"testing"

	"safeguard/pkg/config"

	"github.com/stretchr/testify/assert"
)

func Test_Attach(t *testing.T) {
	t.Run("expect to be attach BPF Program", func(t *testing.T) {
		config := config.DefaultConfig()
		ctrl := createController(config)
		defer ctrl.bpfModule.Close()

		actual := ctrl.Attach()
		assert.Equal(t, nil, actual)
	})
}

func Test_SetConfigMap(t *testing.T) {
	t.Run("expect to set config map successfully", func(t *testing.T) {
		config := config.DefaultConfig()
		ctrl := createController(config)
		defer ctrl.bpfModule.Close()

		actual := ctrl.SetConfigToMap()
		assert.Equal(t, nil, actual)
	})
}

func createController(conf *config.Config) ProcessController {
	mod, err := initializeBPFModule()
	if err != nil {
		panic(err)
	}

	ctrl := ProcessController{
		bpfModule: mod,
		settings:  conf,
	}

	err = ctrl.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return ctrl
}
