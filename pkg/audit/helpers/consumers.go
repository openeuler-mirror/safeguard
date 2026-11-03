package helpers

import "sync"

// Consumers joins event handlers before their backing module is released.
// Stop the producer before Wait; records already being handled finish normally.
type Consumers struct{ workers sync.WaitGroup }

func (c *Consumers) Go(run func()) {
	c.workers.Add(1)
	go func() { defer c.workers.Done(); run() }()
}

func (c *Consumers) Wait() { c.workers.Wait() }

// DrainLost keeps perf-buffer loss reporting from blocking producer shutdown.
func DrainLost(lost <-chan uint64) {
	for range lost {
	}
}
