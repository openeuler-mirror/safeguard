package process

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"culinux/pkg/audit/helpers"
)

type attachTestLink struct {
	name      string
	destroyed *[]string
}

func (l attachTestLink) Destroy() error {
	*l.destroyed = append(*l.destroyed, l.name)
	return nil
}

func TestProcessAttachRollsBackWhenLSMFails(t *testing.T) {
	cause := errors.New("LSM unavailable")
	var destroyed []string
	err := attachProcessPrograms(func(name string) (helpers.Link, error) {
		if name == "restricted_process_bprm_check" {
			return nil, cause
		}
		return attachTestLink{name, &destroyed}, nil
	})
	if !errors.Is(err, cause) || !reflect.DeepEqual(destroyed, []string{BPF_PROGRAM_EXEC, BPF_PROGRAM_FORK}) {
		t.Fatalf("err=%v, destroyed=%v", err, destroyed)
	}
}

type lifecycleBuffer struct{ stops, closes int }

func (b *lifecycleBuffer) Start() {}
func (b *lifecycleBuffer) Stop()  { b.stops++ }
func (b *lifecycleBuffer) Close() { b.closes++ }

func TestManagerLifecycleSafety(t *testing.T) {
	var empty Manager
	empty.Stop()
	empty.Close()
	empty.Close()
	buffer := new(lifecycleBuffer)
	ring := new(lifecycleBuffer)
	mgr := Manager{pb: buffer, rb: ring}
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); mgr.Stop(); mgr.Close() }()
	}
	workers.Wait()
	if buffer.stops != 1 || buffer.closes != 1 {
		t.Fatalf("stops=%d closes=%d", buffer.stops, buffer.closes)
	}
	if ring.stops != 1 || ring.closes != 1 {
		t.Fatalf("ring: %+v", ring)
	}
	if err := mgr.StartExecAudit(nil, nil); err == nil {
		t.Fatal("started closed ring manager")
	}
	if err := mgr.Start(nil, nil); err == nil {
		t.Fatal("started closed manager")
	}
}
