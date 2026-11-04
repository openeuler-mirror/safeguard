package network

import (
	"context"
	"math/rand"
	"time"
)

type refreshRetry struct {
	failures uint
	rng      *rand.Rand
}

func (r *refreshRetry) base(ttl uint32, err error) time.Duration {
	if err == nil {
		r.failures = 0
		return refreshDelay(ttl)
	}
	delay := 5 * time.Second
	for i := uint(0); i < r.failures; i++ {
		delay *= 2
	}
	if delay > time.Minute {
		delay = time.Minute
	}
	if r.failures < 4 {
		r.failures++
	}
	return delay
}

func waitRefresh(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (r *refreshRetry) next(ttl uint32, err error) time.Duration {
	if r.rng == nil {
		r.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	delay := r.base(ttl, err)
	delay -= time.Duration(r.rng.Int63n(int64(delay/5) + 1))
	if delay < time.Second {
		return time.Second
	}
	return delay
}
