package mount

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"culinux/pkg/audit/helpers"
	"culinux/pkg/config"
	log "culinux/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	MOUNT_CONFIG             = "mount_safeguard_config_map"
	MOUNT_DENIED_SOURCE_LIST = "mount_denied_source_list"
	MODE_MONITOR             = uint32(0)
	MODE_BLOCK               = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)
)

// Manager handles mount audit events and BPF map operations for mount restriction.
type Manager struct {
	lifecycleMu sync.Mutex
	stopped     bool
	closed      bool
	mod         *libbpfgo.Module
	config      *config.Config
	pb          helpers.Buffer
}

// Start initializes the perf buffer for mount events and begins polling.
func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed || m.stopped || m.pb != nil {
		return fmt.Errorf("mount buffer cannot be restarted")
	}
	pb, err := helpers.StartBuffer("mount_events", func() (helpers.Buffer, error) {
		return m.mod.InitPerfBuf("mount_events", eventChannel, lostChannel, 1024)
	})
	if err != nil {
		return err
	}

	m.pb = pb

	return nil
}

// Stop halts the perf buffer polling for mount events.
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

// Close releases the perf buffer resources.
func (m *Manager) Close() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	m.stopLocked()
	if m.pb != nil {
		m.pb.Close()
	}
}

// Attach attaches the BPF LSM programs for mount restriction.
func (m *Manager) Attach() error {
	return helpers.AttachAll(BPF_PROGRAM_NAME, func(name string) (helpers.Link, error) {
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

	map_denied_source_paths, err := m.mod.GetMap(MOUNT_DENIED_SOURCE_LIST)
	if err != nil {
		return err
	}

	denied_source_paths := config.UniqueStrings(m.config.RestrictedMountConfig.DenySourcePath)
	for i, path := range denied_source_paths {
		key := uint32(i)
		value := make([]byte, PATH_MAX)
		copy(value, path)
		err = map_denied_source_paths.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setModeAndTarget() error {
	key := make([]byte, 8)
	configMap, err := m.mod.GetMap(MOUNT_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("mount") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	if m.config.IsOnlyContainer("mount") {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_HOST)
	}

	err = helpers.UpdateConfigMap(configMap, key)
	if err != nil {
		return err
	}

	return nil
}
