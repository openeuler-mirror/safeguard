package mount

import (
	"sync"
	"testing"
)

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
