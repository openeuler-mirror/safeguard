package helpers

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// Consumers joins event handlers before their backing module is released.
// Stop the producer after Await and before Wait; in-flight records finish normally.
type Consumers struct {
	workers  sync.WaitGroup
	once     sync.Once
	mu       sync.Mutex
	failed   chan struct{}
	stopping bool
	err      error
}

func (c *Consumers) Go(run func()) {
	c.once.Do(func() { c.failed = make(chan struct{}) })
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		completed := false
		defer func() {
			value := recover()
			c.mu.Lock()
			defer c.mu.Unlock()
			var err error
			if !completed {
				if cause, ok := value.(error); ok {
					err = fmt.Errorf("event consumer panic: %w", cause)
				} else {
					err = fmt.Errorf("event consumer panic: %v", value)
				}
			} else if !c.stopping {
				err = fmt.Errorf("event consumer stopped unexpectedly: %w", io.ErrUnexpectedEOF)
			}
			if err != nil && c.err == nil {
				c.err = err
				close(c.failed)
			}
		}()
		run()
		completed = true
	}()
}

// Await requests producer shutdown on cancellation or the first consumer failure.
func (c *Consumers) Await(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-c.failed:
	}
	c.mu.Lock()
	c.stopping = true
	c.mu.Unlock()
}

func (c *Consumers) Wait() error {
	c.workers.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// DrainLost keeps perf-buffer loss reporting from blocking producer shutdown.
func DrainLost(lost <-chan uint64) {
	for range lost {
	}
}
