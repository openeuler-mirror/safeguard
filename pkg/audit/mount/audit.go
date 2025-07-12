package mount

import (
	"C"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"

	"safeguard/pkg/audit/helpers"
	"safeguard/pkg/bpf"
	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	BPF_OBJ_NAME     = "restricted-mount"
	AUDIT_MODULE     = "mount"
	UTS_NAME_LEN     = 64
	COMMAND_NAME_LEN = 16
	MAX_PATH_LENGTH  = 255
)

var BPF_HOOK_NAMES = []string{"control_mount", "control_move_mount"}

type MountAuditRecord struct {
	CGroupID      uint64
	ProcessID     uint32
	UserID        uint32
	ResultCode    int32
	HostName      [UTS_NAME_LEN + 1]byte
	TaskCommand   [COMMAND_NAME_LEN]byte
	ParentTaskCmd [COMMAND_NAME_LEN]byte
	MountSource   [MAX_PATH_LENGTH]byte
}

func initializeBPFModule() (*libbpfgo.Module, error) {
	bpfBytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-mount.bpf.o")
	if err != nil {
		return nil, err
	}
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bpfBytecode, BPF_OBJ_NAME)
	if err != nil {
		return nil, err
	}

	if err = bpfModule.BPFLoadObject(); err != nil {
		return nil, err
	}

	return bpfModule, nil
}

func StartMountAudit(ctx context.Context, waitGroup *sync.WaitGroup, appConfig *config.Config) error {
	defer waitGroup.Done()

	if !appConfig.RestrictedMountConfig.Enable {
		log.Info("Mount audit feature is disabled. Shutting down...")
		return nil
	}

	bpfModule, err := initializeBPFModule()
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	auditMgr := Manager{
		bpfModule: bpfModule,
		appConfig: appConfig,
	}

	auditMgr.ApplyConfigToBPFMap()
	if err != nil {
		log.Fatal(err)
	}

	auditMgr.HookPrograms()

	log.Info("Mount audit process started.")
	eventChan := make(chan []byte)
	lostChan := make(chan uint64)
	auditMgr.Launch(eventChan, lostChan)

	go func() {
		for {
			eventData := <-eventChan
			auditEvent, err := decodeEventData(eventData)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error(err)
				continue
			}

			mountLog := createMountLog(auditEvent)
			mountLog.Info()
		}
	}()

	<-ctx.Done()
	auditMgr.Shutdown()
	log.Info("Mount audit process terminated.")

	return nil
}

func createMountLog(event MountAuditRecord) log.RestrictedMountLog {
	baseEvent := log.AuditEventLog{
		Module:     AUDIT_MODULE,
		Action:     resultToAction(event.ResultCode),
		Hostname:   helpers.NodenameToString(event.HostName),
		PID:        event.ProcessID,
		Comm:       helpers.CommToString(event.TaskCommand),
		ParentComm: helpers.CommToString(event.ParentTaskCmd),
	}

	mountEvent := log.RestrictedMountLog{
		AuditEventLog: baseEvent,
		SourcePath:    convertPathToString(event.MountSource),
	}

	return mountEvent
}

func decodeEventData(eventData []byte) (MountAuditRecord, error) {
	dataBuffer := bytes.NewBuffer(eventData)
	var auditEvent MountAuditRecord
	err := binary.Read(dataBuffer, binary.LittleEndian, &auditEvent)
	if err != nil {
		return MountAuditRecord{}, err
	}

	return auditEvent, nil
}

func resultToAction(result int32) string {
	if result == 0 {
		return "ALLOWED"
	}
	return "BLOCKED"
}

func convertPathToString(path [MAX_PATH_LENGTH]byte) string {
	var pathStr string
	for _, char := range path {
		if char != 0x00 {
			pathStr += string(char)
		} else {
			break
		}
	}
	return pathStr
}
