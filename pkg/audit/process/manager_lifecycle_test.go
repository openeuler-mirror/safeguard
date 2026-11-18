package process

import (
	"encoding/binary"
	"errors"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"culinux/pkg/audit/helpers"
)

type processConfigProbe struct {
	writes int
	value  [MAP_SIZE]byte
}

func (p *processConfigProbe) KeySize() int   { return 4 }
func (p *processConfigProbe) ValueSize() int { return MAP_SIZE }
func (p *processConfigProbe) Update(_ unsafe.Pointer, value unsafe.Pointer) error {
	p.writes++
	p.value = *(*[MAP_SIZE]byte)(value)
	return nil
}

func TestProcessHostNamespaceConfig(t *testing.T) {
	cause := errors.New("namespace inaccessible")
	probe := new(processConfigProbe)
	value := make([]byte, MAP_SIZE)
	err := writeProcessConfigMap(probe, value, true, func() (uint32, error) { return 0, cause })
	if !errors.Is(err, cause) || probe.writes != 0 {
		t.Fatalf("err=%v writes=%d", err, probe.writes)
	}
	err = writeProcessConfigMap(probe, value, true, func() (uint32, error) { return 0xf0000001, nil })
	if err != nil || binary.LittleEndian.Uint32(probe.value[12:]) != 0xf0000001 {
		t.Fatalf("err=%v value=%v", err, probe.value)
	}
	err = writeProcessConfigMap(probe, value, false, func() (uint32, error) { t.Fatal("unexpected namespace lookup"); return 0, nil })
	if err != nil || probe.writes != 2 {
		t.Fatalf("err=%v writes=%d", err, probe.writes)
	}
	err = writeProcessConfigMap(probe, nil, true, func() (uint32, error) { t.Fatal("unexpected namespace lookup"); return 0, nil })
	if err == nil || probe.writes != 2 {
		t.Fatalf("err=%v writes=%d", err, probe.writes)
	}
}

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
