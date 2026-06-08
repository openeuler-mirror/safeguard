package process

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"culinux/pkg/config"
	log "culinux/pkg/log"

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
)

type Manager struct {
	mod    *libbpfgo.Module
	config *config.Config
	pb     *libbpfgo.PerfBuffer
	rb     *libbpfgo.RingBuffer
}

func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	pb, err := m.mod.InitPerfBuf("process_events", eventChannel, lostChannel, 1024)
	if err != nil {
		return err
	}

	pb.Start()
	m.pb = pb

	return nil
}

// StartExecAudit 启动进程执行审计（ringbuf）
func (m *Manager) StartExecAudit(eventChannel chan []byte, lostChannel chan uint64) error {
	rb, err := m.mod.InitRingBuf("process_exec_events", eventChannel)
	if err != nil {
		return err
	}

	rb.Start()
	m.rb = rb

	return nil
}

func (m *Manager) Stop() {
	m.pb.Stop()
	if m.rb != nil {
		m.rb.Stop()
	}
}

func (m *Manager) Close() {
	m.pb.Close()
	if m.rb != nil {
		m.rb.Close()
	}
}

func (m *Manager) Attach() error {
	prog, err := m.mod.GetProgram(BPF_PROGRAM_FORK)
	if err != nil {
		return err
	}

	_, err = prog.AttachTracepoint("sched", "sched_process_fork")
	if err != nil {
		return err
	}

	prog, err = m.mod.GetProgram(BPF_PROGRAM_EXEC)
	if err != nil {
		return err
	}

	_, err = prog.AttachTracepoint("sched", "sched_process_exec")
	if err != nil {
		return err
	}

	// 附加 LSM hook
	lsmProg, err := m.mod.GetProgram("restricted_process_bprm_check")
	if err != nil {
		log.Debug(fmt.Sprintf("LSM program restricted_process_bprm_check not found: %v", err))
	} else {
		_, err = lsmProg.AttachLSM()
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to attach LSM program: %v", err))
		} else {
			log.Debug("restricted_process_bprm_check attached.")
		}
	}

	log.Debug(fmt.Sprintf("%s, %s attached.", BPF_PROGRAM_FORK, BPF_PROGRAM_EXEC))
	return nil
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

	k := uint8(0)
	err = configMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&key[0]))
	if err != nil {
		return err
	}

	return nil
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
