package process

import (
	"fmt"

	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	MODE_MONITOR = uint32(0)
	MODE_BLOCK   = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)
)

type ProcessController struct {
	bpfModule  *libbpfgo.Module
	settings   *config.Config
	eventQueue *libbpfgo.PerfBuffer
}

func (c *ProcessController) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	queue, err := c.bpfModule.InitPerfBuf("process_activity_logs", eventChannel, lostChannel, 1024)
	if err != nil {
		return err
	}

	queue.Start()
	c.eventQueue = queue

	return nil
}

func (c *ProcessController) Stop() {
	c.eventQueue.Stop()
}

func (c *ProcessController) Close() {
	c.eventQueue.Close()
}

func (c *ProcessController) Attach() error {
	prog, err := c.bpfModule.GetProgram(BPF_FORK_IDENTIFIER)
	if err != nil {
		return err
	}

	_, err = prog.AttachTracepoint("sched", "sched_process_fork")
	if err != nil {
		return err
	}

	prog, err = c.bpfModule.GetProgram(BPF_EXEC_IDENTIFIER)
	if err != nil {
		return err
	}

	_, err = prog.AttachTracepoint("sched", "sched_process_exec")
	if err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("%s, %s attached successfully.", BPF_FORK_IDENTIFIER, BPF_EXEC_IDENTIFIER))
	return nil
}

func (c *ProcessController) SetConfigToMap() error {
	return nil
}
