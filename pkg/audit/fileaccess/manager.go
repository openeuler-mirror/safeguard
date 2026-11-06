package fileaccess

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"culinux/pkg/audit/helpers"
	"culinux/pkg/config"
	log "culinux/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	FILEACCESS_CONFIG = "fileopen_safeguard_config_map"
	FILEACCESS_PIN    = "/sys/fs/bpf/file_config"
	MODE_MONITOR      = uint32(0)
	MODE_BLOCK        = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)

	POLICY_BLACKLIST = uint32(0)
	POLICY_WHITELIST = uint32(1)
)

// Manager handles file access audit events and BPF map operations for file access restriction.
type Manager struct {
	lifecycleMu sync.Mutex
	stopped     bool
	closed      bool
	mod         *libbpfgo.Module
	config      *config.Config
	pb          helpers.Buffer
	ownsPin     bool
}

// Start initializes the perf buffer for file access events and begins polling.
func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed || m.stopped || m.pb != nil {
		return fmt.Errorf("fileaccess buffer cannot be restarted")
	}
	pb, err := helpers.StartBuffer("fileopen_events", func() (helpers.Buffer, error) {
		return m.mod.InitPerfBuf("fileopen_events", eventChannel, lostChannel, 1024)
	})
	if err != nil {
		return err
	}

	m.pb = pb

	return nil
}

// Stop halts the perf buffer polling for file access events.
func (m *Manager) Stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopLocked()
}

func (m *Manager) stopLocked() {
	if m.stopped {
		return
	}
	m.stopped = true
	if m.pb != nil {
		m.pb.Stop()
	}
}

// Close unpins the BPF config map and releases the perf buffer.
func (m *Manager) Close() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	m.stopLocked()
	if m.ownsPin {
		m.ownsPin = false
		configMap, err := m.mod.GetMap(FILEACCESS_CONFIG)
		if err == nil {
			if err := configMap.Unpin(FILEACCESS_PIN); err != nil {
				log.Debug(fmt.Sprintf("failed to unpin file_config: %v", err))
			}
		}
	}
	if m.pb != nil {
		m.pb.Close()
	}
}

// Attach attaches the BPF LSM programs for file access restriction.
func (m *Manager) Attach() error {
	return helpers.AttachAll([]string{"restricted_file_open", "restricted_path_unlink", "restricted_file_truncate", "restricted_path_rmdir", "restricted_path_rename", "restricted_file_receive"}, func(name string) (helpers.Link, error) {
		prog, err := m.mod.GetProgram(name)
		if err != nil {
			return nil, err
		}
		link, err := prog.AttachLSM()
		if err == nil {
			log.Debug(fmt.Sprintf("%s attached.", name))
		}
		return link, err
	})
}

func (m *Manager) SetConfigToMap() error {
	err := m.setModeAndTarget()
	if err != nil {
		return err
	}

	err = m.setAllowedFileAccessMap()
	if err != nil {
		return err
	}

	err = m.setDeniedFileAccessMap()
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setAllowedFileAccessMap() error {
	map_allowed_files, err := m.mod.GetMap(ALLOWED_FILES_MAP_NAME)
	if err != nil {
		return err
	}

	allowed_paths := config.UniqueStrings(m.config.RestrictedFileAccessConfig.Allow)

	for i, path := range allowed_paths {
		if path == "" {
			continue
		}
		key := uint32(i)
		value := make([]byte, PATH_MAX)
		copy(value, path)
		err = map_allowed_files.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedFileAccessMap() error {
	map_denied_files, err := m.mod.GetMap(DENIED_FILES_MAP_NAME)
	if err != nil {
		return err
	}

	denied_paths := config.UniqueStrings(m.config.RestrictedFileAccessConfig.Deny)

	for i, path := range denied_paths {
		if path == "" {
			continue
		}
		key := uint32(i)
		value := make([]byte, PATH_MAX)
		copy(value, path)

		keyPtr := unsafe.Pointer(&key)
		valuePtr := unsafe.Pointer(&value[0])
		err = map_denied_files.Update(keyPtr, valuePtr)
		if err != nil {
			return err
		}
	}

	/* kernel version lower than 5.10
	result := ""
	for _, path := range denied_paths {
		result += path
		result += "|"
	}
	key := uint8(0)
	value := []byte(result)
	err = map_denied_files.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
	if err != nil {
		return err
	}
	*/

	return nil
}

// ConfigKeySize is the size of the config key in bytes (3 uint32 fields: mode, target, policy)
const ConfigKeySize = 12

func (m *Manager) setModeAndTarget() error {
	key := make([]byte, ConfigKeySize)
	configMap, err := m.mod.GetMap(FILEACCESS_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("fileaccess") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	if m.config.IsOnlyContainer("fileaccess") {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_HOST)
	}

	// 设置 policy 值
	if m.config.Policy == "whitelist" {
		binary.LittleEndian.PutUint32(key[8:12], POLICY_WHITELIST)
	} else {
		binary.LittleEndian.PutUint32(key[8:12], POLICY_BLACKLIST)
	}

	err = helpers.UpdateConfigMap(configMap, key)
	if err != nil {
		return err
	}
	err = configMap.Pin(FILEACCESS_PIN)
	if err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return err
		}
		if unpinErr := configMap.Unpin(FILEACCESS_PIN); unpinErr != nil {
			return unpinErr
		}
		if pinErr := configMap.Pin(FILEACCESS_PIN); pinErr != nil {
			return pinErr
		}
	}

	m.ownsPin = true
	return nil
}
