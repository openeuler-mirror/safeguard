package mount

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
	BPF_OBJECT_NAME = "restricted-mount"
	MODULE          = "mount"

	NEW_UTS_LEN   = 64
	TASK_COMM_LEN = 16
	PATH_MAX      = 255
)

var BPF_PROGRAM_NAME []string = []string{"restricted_mount", "restricted_move_mount"}

type auditLog struct {
	CGroupID        uint64
	PID             uint32
	UID             uint32
	Ret             int32
	Nodename        [NEW_UTS_LEN + 1]byte
	Command         [TASK_COMM_LEN]byte
	ParentCommand   [TASK_COMM_LEN]byte
	MountSourcePath [PATH_MAX]byte
}

func setupBPFProgram(ctx context.Context) (*libbpfgo.Module, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-mount.bpf.o")
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, BPF_OBJECT_NAME)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		mod.Close()
		return nil, err
	}
	if err = mod.BPFLoadObject(); err != nil {
		mod.Close()
		return nil, err
	}

	return mod, nil
}

func RunAudit(ctx context.Context, wg *sync.WaitGroup, conf *config.Config) error {
	defer wg.Done()

	if !conf.RestrictedMountConfig.Enable {
		log.Info("mount audit is disable. shutdown...")
		return nil
	}

	mod, err := setupBPFProgram(ctx)
	if err != nil {
		return helpers.During("mount", "load", err)
	}

	mgr := Manager{
		mod:    mod,
		config: conf,
	}
	defer helpers.Own(ctx, func() { mgr.Close(); mod.Close() })()

	if err := helpers.StartStage(ctx, "mount", "configure", mgr.SetConfigToMap); err != nil {
		return err
	}

	if err := helpers.StartStage(ctx, "mount", "attach", mgr.Attach); err != nil {
		return err
	}

	log.Info("Start the mount audit.")
	eventChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	if err := helpers.StartStage(ctx, "mount", "buffer", func() error { return mgr.Start(eventChannel, lostChannel) }); err != nil {
		return err
	}

	var consumers helpers.Consumers
	consumers.Go(func() { helpers.DrainLost(lostChannel) })
	helpers.ReportReady(ctx)
	consumers.Go(func() {
		for {
			eventBytes, open := helpers.NextEvent(eventChannel)
			if !open {
				return
			}
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
	})

	consumers.Await(ctx)
	mgr.Stop()
	consumerErr := consumers.Wait()
	mgr.Close()
	log.Info("Terminated the mount audit.")

	return helpers.During("mount", "consume", consumerErr)
}

func newAuditLog(event auditLog) log.RestrictedMountLog {
	auditEvent := log.AuditEventLog{
		Module:     MODULE,
		Action:     retToaction(event.Ret),
		Hostname:   helpers.NodenameToString(event.Nodename),
		PID:        event.PID,
		Comm:       helpers.CommToString(event.Command),
		ParentComm: helpers.CommToString(event.ParentCommand),
	}

	mountLog := log.RestrictedMountLog{
		AuditEventLog: auditEvent,
		SourcePath:    pathToString(event.MountSourcePath),
	}

	return mountLog
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

func retToaction(ret int32) string {
	if ret == 0 {
		return "ALLOWED"
	} else if ret > 0 {
		return "MONITOR"
	} else {
		return "BLOCKED"
	}
}

func pathToString(path [PATH_MAX]byte) string {
	end := bytes.IndexByte(path[:], 0)
	if end < 0 {
		end = len(path)
	}
	return string(path[:end])
}
