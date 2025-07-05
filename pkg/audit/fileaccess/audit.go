package fileaccess

import (
	"C"

	"safeguard/pkg/bpf"
	log "safeguard/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"

	"safeguard/pkg/audit/helpers"
	"safeguard/pkg/config"
)

const (
	BPF_OBJECT_IDENTIFIER    = "secure-file-access"
	BPF_PROGRAM_IDENTIFIER   = "control_file_open"
	PERMITTED_PATHS_MAP_NAME = "permitted_file_paths"
	BLOCKED_PATHS_MAP_NAME   = "blocked_file_paths"
	AUDIT_MODULE             = "access"

	NEW_UTS_LEN   = 64
	PATH_MAX      = 255
	TASK_COMM_LEN = 16
)

type fileAccessLog struct {
	CGroupID      uint64
	PID           uint32
	UID           uint32
	Ret           int32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [TASK_COMM_LEN]byte
	ParentCommand [TASK_COMM_LEN]byte
	Path          [PATH_MAX]byte
}

func initializeBPFModule() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-file.bpf.o")
	if err != nil {
		return nil, err
	}
	module, err := libbpfgo.NewModuleFromBuffer(bytecode, BPF_OBJECT_IDENTIFIER)
	if err != nil {
		return nil, err
	}

	if err = module.BPFLoadObject(); err != nil {
		return nil, err
	}

	return module, nil
}

func StartFileAccessAudit(ctx context.Context, wg *sync.WaitGroup, settings *config.Config) error {
	defer wg.Done()

	if !settings.RestrictedFileAccessConfig.Enable {
		log.Info("File access audit is disabled. Shutting down...")
		return nil
	}

	module, err := initializeBPFModule()
	if err != nil {
		log.Fatal(err)
	}
	defer module.Close()

	controller := FileAccessController{
		bpfModule: module,
		settings:  settings,
	}

	if err := controller.SetConfigToMap(); err != nil {
		log.Fatal(err)
	}

	if err := controller.Attach(); err != nil {
		log.Fatal(err)
	}

	log.Info("Starting file access audit.")
	eventChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	if err := controller.Start(eventChannel, lostChannel); err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			eventData := <-eventChannel
			event, err := decodeEvent(eventData)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error(err)
				continue
			}

			auditLog := createAuditLog(event)
			auditLog.Info()
		}
	}()

	<-ctx.Done()
	controller.Close()
	log.Info("Terminated file access audit.")

	return nil
}

func createAuditLog(event fileAccessLog) log.RestrictedFileAccessLog {
	auditEvent := log.AuditEventLog{
		Module:     AUDIT_MODULE,
		Action:     convertRetToAction(event.Ret),
		Hostname:   helpers.NodenameToString(event.Nodename),
		PID:        event.PID,
		UID:        event.UID,
		Comm:       helpers.CommToString(event.Command),
		ParentComm: helpers.CommToString(event.ParentCommand),
	}

	fileAccessLog := log.RestrictedFileAccessLog{
		AuditEventLog: auditEvent,
		Path:          convertPathToString(event.Path),
	}

	return fileAccessLog
}

func decodeEvent(eventData []byte) (fileAccessLog, error) {
	buf := bytes.NewBuffer(eventData)
	var event fileAccessLog
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return fileAccessLog{}, err
	}

	return event, nil
}

func convertRetToAction(ret int32) string {
	if ret == 0 {
		return "ALLOWED"
	}
	return "BLOCKED"
}

func convertPathToString(path [PATH_MAX]byte) string {
	var result string
	for _, b := range path {
		if b != 0x00 {
			result += string(b)
		} else {
			break
		}
	}
	return result
}
