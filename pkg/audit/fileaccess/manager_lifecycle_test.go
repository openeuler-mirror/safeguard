package fileaccess

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

type fileConfigProbe struct {
	writes int
	value  [ConfigKeySize]byte
}

func (*fileConfigProbe) KeySize() int   { return 4 }
func (*fileConfigProbe) ValueSize() int { return ConfigKeySize }
func (p *fileConfigProbe) Update(_, value unsafe.Pointer) error {
	p.writes++
	p.value = *(*[ConfigKeySize]byte)(value)
	return nil
}

func TestFileHostNamespaceConfig(t *testing.T) {
	p := new(fileConfigProbe)
	value := make([]byte, ConfigKeySize)
	wantErr := errors.New("namespace unavailable")
	if err := writeFileConfigMap(p, value, true, func() (uint32, error) { return 0, wantErr }); !errors.Is(err, wantErr) || p.writes != 0 {
		t.Fatalf("namespace error=%v writes=%d", err, p.writes)
	}
	if err := writeFileConfigMap(p, value[:12], true, nil); err == nil || p.writes != 0 {
		t.Fatalf("short value error=%v writes=%d", err, p.writes)
	}
	if err := writeFileConfigMap(p, value, true, func() (uint32, error) { return 0xf0000001, nil }); err != nil {
		t.Fatal(err)
	}
	if p.writes != 1 || binary.LittleEndian.Uint32(p.value[12:16]) != 0xf0000001 {
		t.Fatalf("writes=%d value=%x", p.writes, p.value)
	}
	if err := writeFileConfigMap(p, make([]byte, ConfigKeySize), false, nil); err != nil || p.writes != 2 {
		t.Fatalf("host config error=%v writes=%d", err, p.writes)
	}
}

func TestFileConfigPinConflict(t *testing.T) {
	for _, cause := range []error{nil, os.ErrExist, os.ErrPermission} {
		calls := 0
		err := pinFileConfig(func(path string) error {
			calls++
			if path != FILEACCESS_PIN {
				t.Fatalf("unexpected pin path: %s", path)
			}
			return cause
		})
		if calls != 1 || !errors.Is(err, cause) {
			t.Fatalf("calls=%d err=%v cause=%v", calls, err, cause)
		}
		if cause == os.ErrExist && !strings.Contains(err.Error(), "verify ownership") {
			t.Fatalf("missing conflict guidance: %v", err)
		}
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
	mgr := Manager{pb: buffer}
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); mgr.Stop(); mgr.Close() }()
	}
	workers.Wait()
	if buffer.stops != 1 || buffer.closes != 1 {
		t.Fatalf("stops=%d closes=%d", buffer.stops, buffer.closes)
	}
	if err := mgr.Start(nil, nil); err == nil {
		t.Fatal("started closed manager")
	}
}
