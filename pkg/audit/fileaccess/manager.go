package fileaccess

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	FILE_SECURITY_CONFIG_MAP = "file_security_config"
	MODE_MONITOR             = uint32(0)
	MODE_BLOCK               = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)

	// BPF Map Names
	PERMITTED_FILE_PATHS_MAP = "permitted_file_paths"
	BLOCKED_FILE_PATHS_MAP   = "blocked_file_paths"
)

type FileAccessController struct {
	bpfModule  *libbpfgo.Module
	settings   *config.Config
	eventQueue *libbpfgo.PerfBuffer
}

func (c *FileAccessController) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	queue, err := c.bpfModule.InitPerfBuf("file_access_logs", eventChannel, lostChannel, 1024)
	if err != nil {
		return err
	}

	queue.Start()
	c.eventQueue = queue

	return nil
}

func (c *FileAccessController) Stop() {
	c.eventQueue.Stop()
}

func (c *FileAccessController) Close() {
	configMap, err := c.bpfModule.GetMap(FILE_SECURITY_CONFIG_MAP)
	if err == nil {
		configMap.Unpin("/sys/fs/bpf/file_security_config")
	}
	c.eventQueue.Close()
}

func (c *FileAccessController) Attach() error {
	for _, progName := range []string{
		"control_file_open",
		"control_path_unlink",
		"control_path_rmdir",
		"control_path_rename",
		"control_file_receive",
	} {
		prog, err := c.bpfModule.GetProgram(progName)
		if err != nil {
			return err
		}

		_, err = prog.AttachLSM()
		if err != nil {
			return err
		}

		log.Debug(fmt.Sprintf("%s attached successfully.", progName))
	}
	return nil
}

func (c *FileAccessController) SetConfigToMap() error {
	if err := c.configureModeAndTarget(); err != nil {
		return err
	}

	if err := c.configurePermittedFileAccess(); err != nil {
		return err
	}

	if err := c.configureBlockedFileAccess(); err != nil {
		return err
	}

	return nil
}

func (c *FileAccessController) configurePermittedFileAccess() error {
	permittedMap, err := c.bpfModule.GetMap(PERMITTED_FILE_PATHS_MAP)
	if err != nil {
		return err
	}

	allowedPaths := c.settings.RestrictedFileAccessConfig.Allow

	for idx, path := range allowedPaths {
		key := uint8(idx)
		value := []byte(path)
		err = permittedMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *FileAccessController) configureBlockedFileAccess() error {
	blockedMap, err := c.bpfModule.GetMap(BLOCKED_FILE_PATHS_MAP)
	if err != nil {
		return err
	}

	deniedPaths := c.settings.RestrictedFileAccessConfig.Deny

	for idx, path := range deniedPaths {
		key := uint8(idx)
		value := []byte(path)

		keyPtr := unsafe.Pointer(&key)
		valuePtr := unsafe.Pointer(&value[0])
		err = blockedMap.Update(keyPtr, valuePtr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *FileAccessController) configureModeAndTarget() error {
	key := make([]byte, 8)
	configMap, err := c.bpfModule.GetMap(FILE_SECURITY_CONFIG_MAP)
	if err != nil {
		return err
	}

	if c.settings.IsRestrictedMode("fileaccess") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	if c.settings.IsOnlyContainer("fileaccess") {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_HOST)
	}

	k := uint8(0)
	err = configMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&key[0]))
	if err != nil {
		return err
	}
	err = configMap.Pin("/sys/fs/bpf/file_security_config")
	if err != nil {
		return err
	}

	return nil
}
