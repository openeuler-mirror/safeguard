package network

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSCacheConcurrentAccess(t *testing.T) {
	cache := newDNSCache()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			addr := fmt.Sprintf("192.0.2.%d", i)
			for j := 0; j < 100; j++ {
				cache.Store(addr, "concurrent.example.")
				_ = cache.Lookup(addr)
				_ = cache.Len()
			}
		}(i)
	}
	workers.Wait()
	require.Equal(t, 8, cache.Len())
	require.Equal(t, "concurrent.example.", cache.Lookup("192.0.2.0"))
}
