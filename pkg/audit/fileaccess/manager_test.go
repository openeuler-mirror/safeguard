package fileaccess

import (
	"bytes"
	"testing"
	"unsafe"

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

func Test_SetConfigMap_AllowedFiles(t *testing.T) {
	tests := []struct {
		name         string
		allowedFiles []string
		deniedFiles  []string
		expected     []byte
	}{
		{
			name:         "test",
			allowedFiles: []string{"/"},
			deniedFiles:  []string{"/etc/passwd"},
			expected:     []byte{0x2f},
		},
	}

	config := config.DefaultConfig()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config.RestrictedFileAccessConfig.Allow = test.allowedFiles
			config.RestrictedFileAccessConfig.Deny = test.deniedFiles
			ctrl := createController(config)
			defer ctrl.bpfModule.Close()

			mapPermittedFiles, err := ctrl.bpfModule.GetMap(PERMITTED_FILE_PATHS_MAP)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", PERMITTED_FILE_PATHS_MAP, err)
			}

			key := uint8(0)
			actual, err := mapPermittedFiles.GetValue(unsafe.Pointer(&key))
			if err != nil {
				t.Fatalf("Failed to get value from eBPF map %s, err: %s", PERMITTED_FILE_PATHS_MAP, err)
			}

			padding := bytes.Repeat([]byte{0x00}, PATH_MAX-len(test.expected))
			expected := append(test.expected, padding...)
			assert.Equal(t, expected, actual)
		})
	}
}

func Test_SetConfigMap_DeniedFiles(t *testing.T) {
	tests := []struct {
		name         string
		allowedFiles []string
		deniedFiles  []string
		expected     []byte
	}{
		{
			name:         "test",
			allowedFiles: []string{"/"},
			deniedFiles:  []string{"/etc/passwd"},
			expected:     []byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x64},
		},
	}

	config := config.DefaultConfig()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config.RestrictedFileAccessConfig.Allow = test.allowedFiles
			config.RestrictedFileAccessConfig.Deny = test.deniedFiles
			ctrl := createController(config)
			defer ctrl.bpfModule.Close()

			mapBlockedFiles, err := ctrl.bpfModule.GetMap(BLOCKED_FILE_PATHS_MAP)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", BLOCKED_FILE_PATHS_MAP, err)
			}

			iter := mapBlockedFiles.Iterator()
			if iter.Next() {
				key := iter.Key()
				keyPtr := unsafe.Pointer(&key[0])
				actual, err := mapBlockedFiles.GetValue(keyPtr)

				if err != nil {
					t.Fatalf("Failed to get value from eBPF map %s, err: %s", BLOCKED_FILE_PATHS_MAP, err)
				}

				padding := bytes.Repeat([]byte{0x00}, PATH_MAX-len(test.expected))
				expected := append(test.expected, padding...)
				assert.Equal(t, expected, actual)
			}
		})
	}
}

func createController(conf *config.Config) FileAccessController {
	mod, err := initializeBPFModule()
	if err != nil {
		panic(err)
	}

	ctrl := FileAccessController{
		bpfModule: mod,
		settings:  conf,
	}

	err = ctrl.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return ctrl
}
