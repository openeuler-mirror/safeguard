package process

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
	BPF_OBJECT_IDENTIFIER = "secure-process-monitor"
	BPF_FORK_IDENTIFIER   = "monitor_process_fork"
	BPF_EXEC_IDENTIFIER   = "monitor_process_exec"
	AUDIT_MODULE          = "process"

	NEW_UTS_LEN      = 64
	PATH_MAX         = 255
	PROCESS_NAME_LEN = 16
)

type processLog struct {
	ProcessID   uint32
	ParentID    uint32
	Nodename    [NEW_UTS_LEN + 1]byte
	ProcessName [PROCESS_NAME_LEN]byte
	ParentName  [PROCESS_NAME_LEN]byte
}

func initializeBPFModule() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-process.bpf.o")
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

func StartProcessAudit(ctx context.Context, wg *sync.WaitGroup, settings *config.Config) error {
	defer wg.Done()

	if !settings.RestrictedProcessConfig.Enable {
		log.Info("Process audit is disabled. Shutting down...")
		return nil
	}

	module, err := initializeBPFModule()
	if err != nil {
		log.Fatal(err)
	}
	defer module.Close()

	controller := ProcessController{
		bpfModule: module,
		settings:  settings,
	}

	if err := controller.SetConfigToMap(); err != nil {
		log.Fatal(err)
	}

	if err := controller.Attach(); err != nil {
		log.Fatal(err)
	}

	log.Info("Starting process audit.")
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
	log.Info("Terminated process audit.")

	return nil
}

func createAuditLog(event processLog) log.RestrictedProcessLog {
	auditEvent := log.AuditEventLog{
		Module:     AUDIT_MODULE,
		Hostname:   helpers.NodenameToString(event.Nodename),
		PID:        event.ProcessID,
		Comm:       helpers.CommToString(event.ProcessName),
		ParentComm: helpers.CommToString(event.ParentName),
	}

	processAccessLog := log.RestrictedProcessLog{
		AuditEventLog: auditEvent,
		PPID:          event.ParentID,
	}

	return processAccessLog
}

func decodeEvent(eventData []byte) (processLog, error) {
	buf := bytes.NewBuffer(eventData)
	var event processLog
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return processLog{}, err
	}

	return event, nil
}
