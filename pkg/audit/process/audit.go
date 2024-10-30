package process

import (
	"C"

	"culinux/pkg/bpf"
	log "culinux/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)
import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"

	"culinux/pkg/audit/helpers"
	"culinux/pkg/config"
)

const (
	BPF_OBJECT_NAME  = "restricted-process"
	BPF_PROGRAM_FORK = "restricted_process_fork"
	BPF_PROGRAM_EXEC = "restricted_process_exec"
	ALLOWED_FILES_MAP_NAME = "allowed_access_files"
	DENIED_FILES_MAP_NAME  = "denied_access_files"

	NEW_UTS_LEN      = 64
	PATH_MAX         = 255
	PROCESS_COMM_LEN = 16
)

type auditLog struct {
	//CGroupID uint64
	PID           uint32
	PPID          uint32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [PROCESS_COMM_LEN]byte
	ParentCommand [PROCESS_COMM_LEN]byte
}

func setupBPFProgram() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-process.bpf.o")
	if err != nil {
		return nil, err
	}
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, BPF_OBJECT_NAME)
	if err != nil {
		return nil, err
	}

	if err = mod.BPFLoadObject(); err != nil {
		return nil, err
	}

	return mod, nil
}

func RunAudit(ctx context.Context, wg *sync.WaitGroup, conf *config.Config) error {
	defer wg.Done()

	if !conf.RestrictedProcessConfig.Enable {
		log.Info("process audit is disable. shutdown...")
		return nil
	}

	mod, err := setupBPFProgram()
	if err != nil {
		log.Fatal(err)
	}
	defer mod.Close()

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	mgr.SetConfigToMap()
	if err != nil {
		log.Fatal(err)
	}

	mgr.Attach()

	log.Info("Start the process audit.")
	eventChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	mgr.Start(eventChannel, lostChannel)

	go func() {
		for {
			eventBytes := <-eventChannel
			event, err := parseEvent(eventBytes)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error(err)
				continue
			}

			auditLog := newAuditLog(event)
			auditLog.Info()
		}
	}()

	<-ctx.Done()
	mgr.Close()
	log.Info("Terminated the process audit.")

	return nil
}

func newAuditLog(event auditLog) log.RestrictedProcessLog {
	auditEvent := log.AuditEventLog{
		//Action:     retToaction(event.Ret),
		Hostname:   helpers.NodenameToString(event.Nodename),
		PID:        event.PID,
		Comm:       helpers.CommToString(event.Command),
		ParentComm: helpers.CommToString(event.ParentCommand),
	}

	processAccessLog := log.RestrictedProcessLog{
		AuditEventLog: auditEvent,
		PPID:          event.PPID,
	}

	return processAccessLog
}

func parseEvent(eventBytes []byte) (auditLog, error) {
	buf := bytes.NewBuffer(eventBytes)
	var event auditLog
	err := binary.Read(buf, binary.LittleEndian, &event)

	if err != nil {
		return auditLog{}, err
	}

	return event, nil
}

// func retToaction(ret int32) string {
// 	if ret == 0 {
// 		return "ALLOWED"
// 	} else {
// 		return "BLOCKED"
// 	}
// }
