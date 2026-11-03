package helpers

import "fmt"

// Buffer is the lifecycle shared by libbpf perf and ring buffers.
type Buffer interface {
	Start()
	Stop()
	Close()
}

// StartBuffer permits initialization faults to be tested without loading BPF.
// A failed initializer must release any allocation it has not returned.
func StartBuffer(name string, initialize func() (Buffer, error)) (Buffer, error) {
	buffer, err := initialize()
	if err != nil {
		return nil, fmt.Errorf("initialize buffer %s: %w", name, err)
	}
	if buffer == nil {
		return nil, fmt.Errorf("initialize buffer %s: nil reader", name)
	}
	buffer.Start()
	return buffer, nil
}
