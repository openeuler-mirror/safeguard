package process

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"culinux/pkg/audit/helpers"
	"culinux/pkg/config"

	"github.com/aquasecurity/libbpfgo"
)

const (
	MODE_MONITOR uint32 = 0
	MODE_BLOCK   uint32 = 1

	TARGET_HOST      uint32 = 0
	TARGET_CONTAINER uint32 = 1

	POLICY_BLACKLIST uint32 = 0
	POLICY_WHITELIST uint32 = 1

	PROCESS_SAFEGUARD_CONFIG_MAP_NAME = "process_safeguard_config_map"
	ALLOWED_PROCESS_LIST_MAP_NAME     = "allowed_process_list"

	TASK_COMM_LEN = 16

	/*
	   +---------------+---------------+---------------+-------------------+
	   | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 | 13 | 14 | 15 | 16 |
	   +---------------+---------------+---------------+-------------------+
	   |      MODE     |     TARGET    |    POLICY     | Allow Process Size|
	   +---------------+---------------+---------------+-------------------+
	*/

	MAP_SIZE                = 16
	MAP_MODE_START          = 0
	MAP_MODE_END            = 4
	MAP_TARGET_START        = 4
	MAP_TARGET_END          = 8
	MAP_POLICY_START        = 8
	MAP_POLICY_END          = 12
	MAP_ALLOW_PROCESS_INDEX = 12
	MAP_HOST_MNT_INDEX      = MAP_ALLOW_PROCESS_INDEX
)

type Manager struct {
	lifecycleMu sync.Mutex
	stopped     bool
	closed      bool
	mod         *libbpfgo.Module
	config      *config.Config
	pb          helpers.Buffer
	rb          helpers.Buffer
}

// Start initializes the perf buffer for process events and begins polling.
func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed || m.stopped || m.pb != nil {
		return fmt.Errorf("process buffer cannot be restarted")
	}
	pb, err := helpers.StartBuffer("process_events", func() (helpers.Buffer, error) {
		return m.mod.InitPerfBuf("process_events", eventChannel, lostChannel, 1024)
	})
	if err != nil {
		return err
	}

	m.pb = pb

	return nil
}

// StartExecAudit 启动进程执行审计（ringbuf）
func (m *Manager) StartExecAudit(eventChannel chan []byte, lostChannel chan uint64) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed || m.stopped || m.rb != nil {
		return fmt.Errorf("process buffer cannot be restarted")
	}
	rb, err := helpers.StartBuffer("process_exec_events", func() (helpers.Buffer, error) {
		return m.mod.InitRingBuf("process_exec_events", eventChannel)
	})
	if err != nil {
		return err
	}

	m.rb = rb

	return nil
}

// Stop halts the perf buffer and ring buffer polling for process events.
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
	if m.rb != nil {
		m.rb.Stop()
	}
}

// Close releases the perf buffer and ring buffer resources.
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
	if m.rb != nil {
		m.rb.Close()
	}
}

// Attach attaches the BPF LSM programs for process restriction.
func (m *Manager) Attach() error {
	return attachProcessPrograms(func(name string) (helpers.Link, error) {
		prog, err := m.mod.GetProgram(name)
		if err != nil {
			return nil, err
		}
		if name == "restricted_process_bprm_check" {
			return prog.AttachLSM()
		}
		point := "sched_process_fork"
		if name == BPF_PROGRAM_EXEC {
			point = "sched_process_exec"
		}
		return prog.AttachTracepoint("sched", point)
	})
}

func attachProcessPrograms(attach func(string) (helpers.Link, error)) error {
	return helpers.AttachAll([]string{BPF_PROGRAM_FORK, BPF_PROGRAM_EXEC, "restricted_process_bprm_check"}, attach)
}

func (m *Manager) SetConfigToMap() error {
	if err := m.setConfigMap(); err != nil {
		return err
	}

	if err := m.setAllowedProcessList(); err != nil {
		return err
	}

	return nil
}

func (m *Manager) setConfigMap() error {
	configMap, err := m.mod.GetMap(PROCESS_SAFEGUARD_CONFIG_MAP_NAME)
	if err != nil {
		return err
	}

	key := make([]byte, MAP_SIZE)

	// 设置 mode
	if m.config.IsRestrictedMode("process") {
		binary.LittleEndian.PutUint32(key[MAP_MODE_START:MAP_MODE_END], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_MODE_START:MAP_MODE_END], MODE_MONITOR)
	}

	// 设置 target
	if m.config.IsOnlyContainer("process") {
		binary.LittleEndian.PutUint32(key[MAP_TARGET_START:MAP_TARGET_END], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_TARGET_START:MAP_TARGET_END], TARGET_HOST)
	}

	// 设置 policy
	if m.config.Policy == "whitelist" {
		binary.LittleEndian.PutUint32(key[MAP_POLICY_START:MAP_POLICY_END], POLICY_WHITELIST)
	} else {
		binary.LittleEndian.PutUint32(key[MAP_POLICY_START:MAP_POLICY_END], POLICY_BLACKLIST)
	}

	// 设置 allow process size
	binary.LittleEndian.PutUint32(key[MAP_ALLOW_PROCESS_INDEX:MAP_ALLOW_PROCESS_INDEX+4], uint32(len(m.config.RestrictedProcessConfig.Allow)))

	return writeProcessConfigMap(configMap, key, m.config.IsOnlyContainer("process"), helpers.HostMountNamespace)
}

func writeProcessConfigMap(m interface {
	KeySize() int
	ValueSize() int
	Update(unsafe.Pointer, unsafe.Pointer) error
}, value []byte, container bool, hostNamespace func() (uint32, error)) error {
	if container {
		if len(value) < MAP_HOST_MNT_INDEX+4 {
			return fmt.Errorf("process configuration payload is too short")
		}
		inode, err := hostNamespace()
		if err != nil {
			return fmt.Errorf("identify host mount namespace: %w", err)
		}
		binary.LittleEndian.PutUint32(value[MAP_HOST_MNT_INDEX:MAP_HOST_MNT_INDEX+4], inode)
	}
	return helpers.UpdateConfigMap(m, value)
}

func (m *Manager) setAllowedProcessList() error {
	processMap, err := m.mod.GetMap(ALLOWED_PROCESS_LIST_MAP_NAME)
	if err != nil {
		return err
	}

	for _, proc := range m.config.RestrictedProcessConfig.Allow {
		// 截断进程名到16字节
		key := byteToProcessKey([]byte(proc))
		value := uint32(0) // BPF map value是u32
		err = processMap.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}

	return nil
}

func byteToProcessKey(b []byte) []byte {
	key := make([]byte, TASK_COMM_LEN)
	copy(key[0:], b)
	return key
}
