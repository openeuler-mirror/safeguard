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

	"github.com/sirupsen/logrus"
)

const (
	BPF_OBJECT_NAME     = "restricted-process"
	BPF_PROGRAM_FORK    = "restricted_process_fork"
	BPF_PROGRAM_EXEC    = "restricted_process_exec"
	MODULE              = "process"

	NEW_UTS_LEN         = 64
	PATH_MAX            = 255
	PROCESS_COMM_LEN    = 16
)

// Action 常量
const (
	ACTION_MONITOR = 0
	ACTION_BLOCK   = 1
)

type auditLog struct {
	//CGroupID uint64
	PID           uint32
	PPID          uint32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [PROCESS_COMM_LEN]byte
	ParentCommand [PROCESS_COMM_LEN]byte
}

// processExecEvent 进程执行审计事件（来自 LSM hook）
type processExecEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	Action      uint8
	Nodename    [NEW_UTS_LEN + 1]byte
	Comm        [PROCESS_COMM_LEN]byte
	ParentComm  [PROCESS_COMM_LEN]byte
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

	if err := mgr.SetConfigToMap(); err != nil {
		log.Fatal(err)
	}

	mgr.Attach()

	log.Info("Start the process audit.")

	// 处理 tracepoint 事件（fork/exec）
	eventChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	mgr.Start(eventChannel, lostChannel)

	// 处理 LSM hook ringbuf 事件（进程执行审计）
	execEventChannel := make(chan []byte)
	execLostChannel := make(chan uint64)
	if err := mgr.StartExecAudit(execEventChannel, execLostChannel); err != nil {
		log.Info("Failed to start exec audit: " + err.Error())
	}
	_ = execLostChannel // unused

	// 处理 tracepoint 事件
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

	// 处理 LSM hook 执行审计事件
	go func() {
		for {
			eventBytes := <-execEventChannel
			event, err := parseExecEvent(eventBytes)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error(err)
				continue
			}

			action := "MONITOR"
			if event.Action == ACTION_BLOCK {
				action = "BLOCKED"
			}

			log.WithFields(logrus.Fields{
				"Module":     MODULE,
				"Action":     action,
				"Hostname":   helpers.NodenameToString(event.Nodename),
				"PID":        event.PID,
				"PPID":       event.PPID,
				"UID":        event.UID,
				"Comm":       helpers.CommToString(event.Comm),
				"ParentComm": helpers.CommToString(event.ParentComm),
			}).Info("Process exec is trapped in the filter.")
		}
	}()

	<-ctx.Done()
	mgr.Close()
	log.Info("Terminated the process audit.")

	return nil
}

func newAuditLog(event auditLog) log.RestrictedProcessLog {
	auditEvent := log.AuditEventLog{
		Module: MODULE,
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

// parseExecEvent 解析进程执行审计事件
func parseExecEvent(eventBytes []byte) (processExecEvent, error) {
	buf := bytes.NewBuffer(eventBytes)
	var event processExecEvent
	err := binary.Read(buf, binary.LittleEndian, &event)

	if err != nil {
		return processExecEvent{}, err
	}

	return event, nil
}
