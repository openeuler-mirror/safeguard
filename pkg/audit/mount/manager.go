package mount

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	MOUNT_CONFIG_MAP     = "mount_protection_config"
	MOUNT_DENY_PATHS_MAP = "mount_blocked_paths"
	MONITOR_MODE         = uint32(0)
	BLOCK_MODE           = uint32(1)
	HOST_TARGET          = uint32(0)
	CONTAINER_TARGET     = uint32(1)
)

type Manager struct {
	bpfModule *libbpfgo.Module
	appConfig *config.Config
	perfBuf   *libbpfgo.PerfBuffer
}

func (mgr *Manager) Launch(eventChan chan []byte, lostChan chan uint64) error {
	perfBuffer, err := mgr.bpfModule.InitPerfBuf("mount_audit_events", eventChan, lostChan, 1024)
	if err != nil {
		return err
	}

	perfBuffer.Start()
	mgr.perfBuf = perfBuffer

	return nil
}

func (mgr *Manager) Pause() {
	mgr.perfBuf.Stop()
}

func (mgr *Manager) Shutdown() {
	mgr.perfBuf.Close()
}

func (mgr *Manager) HookPrograms() error {
	for _, hookName := range BPF_HOOK_NAMES {
		bpfProg, err := mgr.bpfModule.GetProgram(hookName)
		if err != nil {
			return err
		}
		_, err = bpfProg.AttachLSM()
		if err != nil {
			return err
		}
	}

	log.Debug(fmt.Sprintf("BPF programs %v attached successfully.", BPF_HOOK_NAMES))
	return nil
}

func (mgr *Manager) ApplyConfigToBPFMap() error {
	err := mgr.configureModeAndTarget()
	if err != nil {
		return err
	}

	deniedPathsMap, err := mgr.bpfModule.GetMap(MOUNT_DENY_PATHS_MAP)
	if err != nil {
		return err
	}

	deniedPaths := mgr.appConfig.RestrictedMountConfig.DenySourcePath
	for idx, path := range deniedPaths {
		key := uint8(idx)
		pathBytes := []byte(path)
		err = deniedPathsMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&pathBytes[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (mgr *Manager) configureModeAndTarget() error {
	configKey := make([]byte, 8)
	configMap, err := mgr.bpfModule.GetMap(MOUNT_CONFIG_MAP)
	if err != nil {
		return err
	}

	if mgr.appConfig.IsRestrictedMode("mount") {
		binary.LittleEndian.PutUint32(configKey[0:4], BLOCK_MODE)
	} else {
		binary.LittleEndian.PutUint32(configKey[0:4], MONITOR_MODE)
	}

	if mgr.appConfig.IsOnlyContainer("mount") {
		binary.LittleEndian.PutUint32(configKey[4:8], CONTAINER_TARGET)
	} else {
		binary.LittleEndian.PutUint32(configKey[4:8], HOST_TARGET)
	}

	keyIdx := uint8(0)
	err = configMap.Update(unsafe.Pointer(&keyIdx), unsafe.Pointer(&configKey[0]))
	if err != nil {
		return err
	}

	return nil
}
