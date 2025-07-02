package process

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
		mgr := createManager(config)
		defer mgr.mod.Close()

		actual := mgr.Attach()
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
			mgr := createManager(config)
			defer mgr.mod.Close()

			map_allowed_files, err := mgr.mod.GetMap(ALLOWED_FILES_MAP_NAME)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", ALLOWED_FILES_MAP_NAME, err)
			}

			key := uint8(0)
			actual, err := map_allowed_files.GetValue(unsafe.Pointer(&key))
			if err != nil {
				t.Fatalf("Failed to get value from eBPF map %s, err: %s", ALLOWED_FILES_MAP_NAME, err)
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
			mgr := createManager(config)
			defer mgr.mod.Close()

			map_denied_files, err := mgr.mod.GetMap(DENIED_FILES_MAP_NAME)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", DENIED_FILES_MAP_NAME, err)
			}

			iter := map_denied_files.Iterator()
			if iter.Next() {
				key := iter.Key()
				keyPtr := unsafe.Pointer(&key[0])
				actual, err := map_denied_files.GetValue(keyPtr)

				if err != nil {
					t.Fatalf("Failed to get value from eBPF map %s, err: %s", DENIED_FILES_MAP_NAME, err)
				}

				padding := bytes.Repeat([]byte{0x00}, PATH_MAX-len(test.expected))
				expected := append(test.expected, padding...)
				assert.Equal(t, expected, actual)
			}
		})
	}
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
