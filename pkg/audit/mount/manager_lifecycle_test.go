package mount

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"unsafe"
)

type mountConfigProbe struct {
	writes int
	value  [12]byte
}

func (*mountConfigProbe) KeySize() int   { return 4 }
func (*mountConfigProbe) ValueSize() int { return 12 }
func (p *mountConfigProbe) Update(_, value unsafe.Pointer) error {
	p.writes++
	p.value = *(*[12]byte)(value)
	return nil
}

func TestMountHostNamespaceConfig(t *testing.T) {
	p := new(mountConfigProbe)
	value := make([]byte, 12)
	wantErr := errors.New("namespace unavailable")
	if err := writeMountConfigMap(p, value, true, func() (uint32, error) { return 0, wantErr }); !errors.Is(err, wantErr) || p.writes != 0 {
		t.Fatalf("namespace error=%v writes=%d", err, p.writes)
	}
	if err := writeMountConfigMap(p, value[:8], true, nil); err == nil || p.writes != 0 {
		t.Fatalf("short value error=%v writes=%d", err, p.writes)
	}
	if err := writeMountConfigMap(p, value, true, func() (uint32, error) { return 0xf0000001, nil }); err != nil {
		t.Fatal(err)
	}
	if p.writes != 1 || binary.LittleEndian.Uint32(p.value[8:12]) != 0xf0000001 {
		t.Fatalf("writes=%d value=%x", p.writes, p.value)
	}
	if err := writeMountConfigMap(p, make([]byte, 12), false, nil); err != nil || p.writes != 2 {
		t.Fatalf("host config error=%v writes=%d", err, p.writes)
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

func TestNormalizeMountSource(t *testing.T) {
	for input, want := range map[string]string{"/": "/", "/tmp/": "/tmp", "tmpfs/": "tmpfs/", "overlay": "overlay"} {
		if got := normalizeMountSource(input); got != want {
			t.Errorf("source %q: got %q, want %q", input, got, want)
		}
	}
}
