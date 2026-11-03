package helpers

import (
	"context"
	"sync"
)

type readinessKey struct{}

// WithReadiness associates a one-shot startup notification with a task.
func WithReadiness(ctx context.Context, ready func()) context.Context {
	var once sync.Once
	return context.WithValue(ctx, readinessKey{}, func() { once.Do(ready) })
}

// ReportReady marks completion of the module's synchronous startup steps.
func ReportReady(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if ready, ok := ctx.Value(readinessKey{}).(func()); ok {
		ready()
	}
}
