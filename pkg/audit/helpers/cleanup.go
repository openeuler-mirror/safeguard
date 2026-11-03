package helpers

import (
	"context"
	"sync"
)

type cleanupKey struct{}
type cleanupStack struct {
	mu      sync.Mutex
	closed  bool
	entries []func()
}

// WithCleanup transfers registered resource ownership to the caller of close.
func WithCleanup(ctx context.Context) (context.Context, func()) {
	s := &cleanupStack{}
	return context.WithValue(ctx, cleanupKey{}, s), func() {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.closed = true
		entries := s.entries
		s.entries = nil
		s.mu.Unlock()
		for i := len(entries) - 1; i >= 0; i-- {
			entries[i]()
		}
	}
}

// Own registers cleanup for coordinated runs, or returns a local defer otherwise.
func Own(ctx context.Context, release func()) func() {
	var once sync.Once
	close := func() { once.Do(release) }
	if s, ok := ctx.Value(cleanupKey{}).(*cleanupStack); ok {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			close()
		} else {
			s.entries = append(s.entries, close)
			s.mu.Unlock()
		}
		return func() {}
	}
	return close
}
