package network

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

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
				cache.Store(addr, "concurrent.example.", 60)
				_ = cache.Lookup(addr)
				_ = cache.Len()
			}
		}(i)
	}
	workers.Wait()
	require.Equal(t, 8, cache.Len())
	require.Equal(t, "concurrent.example.", cache.Lookup("192.0.2.0"))
}

func TestDNSCacheOwner(t *testing.T) {
	first := Manager{dnsCache: newDNSCache()}
	second := Manager{dnsCache: newDNSCache()}
	answer := &DNSAnswer{Addresses: []net.IP{net.IPv4(192, 0, 2, 1)}, TTL: 60}
	updateDNSCache("first.example.", answer, first.dnsCache)
	updateDNSCache("second.example.", answer, second.dnsCache)
	body := detectEventIPv4{DstIP: [4]byte{192, 0, 2, 1}}
	require.Equal(t, "first.example.", newAuditLog(eventHeader{}, body, first.dnsCache).Domain)
	require.Equal(t, "second.example.", newAuditLog(eventHeader{}, body, second.dnsCache).Domain)
	require.Empty(t, newAuditLog(eventHeader{}, body, nil).Domain)
}

func TestDNSCacheExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	cache := newDNSCache()
	cache.now = func() time.Time { return now }
	cache.Store("192.0.2.1", "expires.example.", 2)
	now = now.Add(time.Second)
	require.Equal(t, "expires.example.", cache.Lookup("192.0.2.1"))
	now = now.Add(time.Second)
	require.Empty(t, cache.Lookup("192.0.2.1"))
	require.Zero(t, cache.Len())
	cache.Store("192.0.2.1", "zero.example.", 0)
	require.Empty(t, cache.Lookup("192.0.2.1"))
}
